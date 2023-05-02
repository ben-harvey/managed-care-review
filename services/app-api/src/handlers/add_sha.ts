import { Handler } from 'aws-lambda'
import { configurePostgres } from './configuration'
import { NewPostgresStore } from '../postgres/postgresStore'
import { HealthPlanRevisionTable } from '@prisma/client'
import {
    HealthPlanFormDataType,
    SubmissionDocument,
} from '../../../app-web/src/common-code/healthPlanFormDataType'
import { toDomain } from '../../../app-web/src/common-code/proto/healthPlanFormDataProto'
import { isStoreError, StoreError } from '../postgres/storeError'
import { S3 } from 'aws-sdk'
import { createHash } from 'crypto'
import { Store } from '../postgres'

const s3 = new S3()

const calculateSHA256 = async (s3URL: string): Promise<string> => {
    const s3Object = await s3
        .getObject({
            Bucket: 'uploads-ma3281shainproto-uploads-121499393294/allusers/' as string,
            Key: s3URL,
        })
        .promise()

    const hash = createHash('sha256')
    hash.update(s3Object.Body as Buffer)
    return hash.digest('hex')
}

const updateDocumentsSHA256 = async (
    documents: SubmissionDocument[]
): Promise<SubmissionDocument[]> => {
    for (const document of documents) {
        const sha256 = await calculateSHA256(document.s3URL)
        document.sha256 = sha256
    }
    return documents
}

const processRevisions = async (
    store: Store,
    pkgID: string,
    revisions: HealthPlanRevisionTable[]
): Promise<void> => {
    for (const revision of revisions) {
        const decodedFormDataProto = toDomain(revision.formDataProto)
        if (!(decodedFormDataProto instanceof Error)) {
            const formData = decodedFormDataProto as HealthPlanFormDataType

            formData.documents = await updateDocumentsSHA256(formData.documents)
            formData.contractDocuments = await updateDocumentsSHA256(
                formData.contractDocuments
            )
            for (const rateInfo of formData.rateInfos) {
                rateInfo.rateDocuments = await updateDocumentsSHA256(
                    rateInfo.rateDocuments
                )
            }

            await store.updateHealthPlanRevision(pkgID, revision.id, formData)
        }
    }
}

export const main: Handler = async (event, context) => {
    const dbURL = process.env.DATABASE_URL
    const secretsManagerSecret = process.env.SECRETS_MANAGER_SECRET
    const pkgID = event.pkgID

    if (!dbURL) {
        console.error('DATABASE_URL not set')
        throw new Error('Init Error: DATABASE_URL is required to run app-api')
    }
    if (!secretsManagerSecret) {
        console.error('SECRETS_MANAGER_SECRET not set')
    }

    const pgResult = await configurePostgres(dbURL, secretsManagerSecret)
    if (pgResult instanceof Error) {
        console.error(
            "Init Error: Postgres couldn't be configured in data exporter"
        )
        throw pgResult
    } else {
        console.info('Postgres configured in data exporter')
    }
    const store = NewPostgresStore(pgResult)

    if (!pkgID) {
        console.error('Package ID is missing in event object')
        throw new Error('Package ID is required')
    }

    const result: HealthPlanRevisionTable[] | StoreError =
        await store.findAllRevisions()
    if (isStoreError(result)) {
        console.error('Error getting revisions from db')
        throw new Error('Error getting records; cannot generate report')
    }

    await processRevisions(store, pkgID, result)

    console.info('SHA256 update complete')
}
