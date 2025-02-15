import { ForbiddenError, UserInputError } from 'apollo-server-lambda'
import {
    UnlockedHealthPlanFormDataType,
    LockedHealthPlanFormDataType,
} from '../../../../app-web/src/common-code/healthPlanFormDataType'
import { toDomain } from '../../../../app-web/src/common-code/proto/healthPlanFormDataProto'
import {
    isCMSUser,
    UpdateInfoType,
    HealthPlanPackageType,
    packageStatus,
    packageSubmitters,
} from '../../domain-models'
import { Emailer } from '../../emailer'
import { MutationResolvers } from '../../gen/gqlServer'
import { logError, logSuccess } from '../../logger'
import { isStoreError, Store } from '../../postgres'
import {
    setErrorAttributesOnActiveSpan,
    setResolverDetailsOnActiveSpan,
    setSuccessAttributesOnActiveSpan,
} from '../attributeHelper'
import { EmailParameterStore } from '../../parameterStore'
import { GraphQLError } from 'graphql'

// unlock is a state machine transforming a LockedFormData and turning it into UnlockedFormData
// Since Unlocked is a strict subset of Locked, this can't error today.
function unlock(
    submission: LockedHealthPlanFormDataType
): UnlockedHealthPlanFormDataType {
    const draft: UnlockedHealthPlanFormDataType = {
        ...submission,
        status: 'DRAFT',
    }
    // this method does persist the submittedAt field onto the draft, but typescript won't let
    // us access it so that's fine.

    return draft
}

// unlockHealthPlanPackageResolver is a state machine transition for HealthPlanPackage
export function unlockHealthPlanPackageResolver(
    store: Store,
    emailer: Emailer,
    emailParameterStore: EmailParameterStore
): MutationResolvers['unlockHealthPlanPackage'] {
    return async (_parent, { input }, context) => {
        const { user, span } = context
        const { unlockedReason, pkgID } = input
        setResolverDetailsOnActiveSpan('unlockHealthPlanPackage', user, span)
        span?.setAttribute('mcreview.package_id', pkgID)

        // This resolver is only callable by CMS users
        if (!isCMSUser(user)) {
            logError(
                'unlockHealthPlanPackage',
                'user not authorized to unlock package'
            )
            setErrorAttributesOnActiveSpan(
                'user not authorized to unlock package',
                span
            )
            throw new ForbiddenError('user not authorized to unlock package')
        }

        // fetch from the store
        const result = await store.findHealthPlanPackage(pkgID)

        if (isStoreError(result)) {
            const errMessage = `Issue finding a package of type ${result.code}. Message: ${result.message}`
            logError('unlockHealthPlanPackage', errMessage)
            setErrorAttributesOnActiveSpan(errMessage, span)
            throw new GraphQLError(errMessage, {
                extensions: {
                    code: 'INTERNAL_SERVER_ERROR',
                    cause: 'DB_ERROR',
                },
            })
        }

        if (result === undefined) {
            const errMessage = `A package must exist to be unlocked: ${pkgID}`
            logError('unlockHealthPlanPackage', errMessage)
            setErrorAttributesOnActiveSpan(errMessage, span)
            throw new UserInputError(errMessage, {
                argumentName: 'pkgID',
            })
        }

        const pkg: HealthPlanPackageType = result
        const pkgStatus = packageStatus(pkg)
        const currentRevision = pkg.revisions[0]

        // Check that the package is in an unlockable state
        if (pkgStatus === 'UNLOCKED' || pkgStatus === 'DRAFT') {
            const errMessage = 'Attempted to unlock package with wrong status'
            logError('unlockHealthPlanPackage', errMessage)
            setErrorAttributesOnActiveSpan(errMessage, span)
            throw new GraphQLError(errMessage, {
                extensions: {
                    code: 'INTERNAL_SERVER_ERROR',
                    cause: 'INVALID_PACKAGE_STATUS',
                },
            })
        }

        // pull the current revision out to unlock it.
        const formDataResult = toDomain(currentRevision.formDataProto)
        if (formDataResult instanceof Error) {
            const errMessage = `Failed to decode proto ${formDataResult}.`
            logError('unlockHealthPlanPackage', errMessage)
            throw new GraphQLError(errMessage, {
                extensions: {
                    code: 'INTERNAL_SERVER_ERROR',
                    cause: 'PROTO_DECODE_ERROR',
                },
            })
        }

        if (formDataResult.status !== 'SUBMITTED') {
            const errMessage = `A locked package had unlocked formData.`
            logError('unlockHealthPlanPackage', errMessage)
            throw new GraphQLError(errMessage, {
                extensions: {
                    code: 'INTERNAL_SERVER_ERROR',
                    cause: 'INVALID_PACKAGE_STATUS',
                },
            })
        }

        const draftformData: UnlockedHealthPlanFormDataType =
            unlock(formDataResult)

        // Create a new revision with this draft in it
        const updateInfo: UpdateInfoType = {
            updatedAt: new Date(),
            updatedBy: context.user.email,
            updatedReason: unlockedReason,
        }

        const unlockedPackage = await store.insertHealthPlanRevision(
            pkgID,
            updateInfo,
            draftformData
        )

        if (isStoreError(unlockedPackage)) {
            const errMessage = `Issue unlocking a package of type ${unlockedPackage.code}. Message: ${unlockedPackage.message}`
            logError('unlockHealthPlanPackage', errMessage)
            setErrorAttributesOnActiveSpan(errMessage, span)
            throw new GraphQLError(errMessage, {
                extensions: {
                    code: 'INTERNAL_SERVER_ERROR',
                    cause: 'DB_ERROR',
                },
            })
        }

        // Send emails!

        // Get state analysts emails from parameter store
        let stateAnalystsEmails =
            await emailParameterStore.getStateAnalystsEmails(
                draftformData.stateCode
            )
        //If error, log it and set stateAnalystsEmails to empty string as to not interrupt the emails.
        if (stateAnalystsEmails instanceof Error) {
            logError('getStateAnalystsEmails', stateAnalystsEmails.message)
            setErrorAttributesOnActiveSpan(stateAnalystsEmails.message, span)
            stateAnalystsEmails = []
        }

        // Get submitter email from every pkg submitted revision.
        const submitterEmails = packageSubmitters(unlockedPackage)

        const statePrograms = store.findStatePrograms(draftformData.stateCode)

        if (statePrograms instanceof Error) {
            logError('findStatePrograms', statePrograms.message)
            setErrorAttributesOnActiveSpan(statePrograms.message, span)
            throw new GraphQLError(statePrograms.message, {
                extensions: {
                    code: 'INTERNAL_SERVER_ERROR',
                    cause: 'DB_ERROR',
                },
            })
        }

        const unlockPackageCMSEmailResult =
            await emailer.sendUnlockPackageCMSEmail(
                draftformData,
                updateInfo,
                stateAnalystsEmails,
                statePrograms
            )

        const unlockPackageStateEmailResult =
            await emailer.sendUnlockPackageStateEmail(
                draftformData,
                updateInfo,
                statePrograms,
                submitterEmails
            )

        if (
            unlockPackageCMSEmailResult instanceof Error ||
            unlockPackageStateEmailResult instanceof Error
        ) {
            if (unlockPackageCMSEmailResult instanceof Error) {
                logError(
                    'unlockPackageCMSEmail - CMS email failed',
                    unlockPackageCMSEmailResult
                )
                setErrorAttributesOnActiveSpan('CMS email failed', span)
            }
            if (unlockPackageStateEmailResult instanceof Error) {
                logError(
                    'unlockPackageStateEmail - state email failed',
                    unlockPackageStateEmailResult
                )
                setErrorAttributesOnActiveSpan('state email failed', span)
            }
            throw new GraphQLError('Email failed.', {
                extensions: {
                    code: 'INTERNAL_SERVER_ERROR',
                    cause: 'EMAIL_ERROR',
                },
            })
        }

        logSuccess('unlockHealthPlanPackage')
        setSuccessAttributesOnActiveSpan(span)

        return { pkg: unlockedPackage }
    }
}
