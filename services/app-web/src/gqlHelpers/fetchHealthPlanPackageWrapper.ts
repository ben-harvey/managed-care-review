import {
    useFetchHealthPlanPackageQuery,
    FetchHealthPlanPackageQuery,
    useFetchHealthPlanPackageWithQuestionsQuery,
} from '../gen/gqlClient'
import { HealthPlanFormDataType } from '../common-code/healthPlanFormDataType'
import { base64ToDomain } from '../common-code/proto/healthPlanFormDataProto'
import {
    wrapApolloResult,
    ApolloResultType,
    QuerySuccessType,
    WrappedApolloResultType,
} from './apolloQueryWrapper'
import { DocumentDateLookupTable } from '../pages/SubmissionSummary/SubmissionSummary'
import { makeDateTableFromFormData } from '../documentHelpers/makeDocumentDateLookupTable'
import {
    LookupListType,
    makeDocumentListFromFormDatas,
} from '../documentHelpers/makeDocumentKeyLookupList'
import { QueryFunctionOptions } from '@apollo/client'

// We return a slightly modified version of the wrapped result adding formDatas
// all of these fields will be added to the SUCCESS type
type AdditionalParsedDataType = {
    formDatas: { [revisionID: string]: HealthPlanFormDataType }
    documentDates: DocumentDateLookupTable
    documentLists: LookupListType
}

type ParsedFetchResultType = ApolloResultType<
    FetchHealthPlanPackageQuery,
    AdditionalParsedDataType
>

type WrappedFetchResultType = WrappedApolloResultType<
    ReturnType<typeof useFetchHealthPlanPackageQuery>,
    AdditionalParsedDataType
>

type WrappedFetchResultWithQuestionsType = WrappedApolloResultType<
    ReturnType<typeof useFetchHealthPlanPackageWithQuestionsQuery>,
    AdditionalParsedDataType
>

function parseProtos(
    result: QuerySuccessType<FetchHealthPlanPackageQuery>
): ParsedFetchResultType {
    const pkg = result.data.fetchHealthPlanPackage.pkg

    if (!pkg) {
        return {
            ...result,
            formDatas: {},
            documentDates: {},
            documentLists: {
                currentDocuments: [],
                previousDocuments: [],
            },
        }
    }

    if (pkg.revisions.length < 1) {
        const err = new Error(
            `useFetchHealthPlanPackageWrapper: submission has no revisions. ID: ${pkg.id}`
        )
        console.error(err)
        return {
            status: 'ERROR',
            error: err,
        }
    }

    const formDatas: { [revisionID: string]: HealthPlanFormDataType } = {}
    for (const revisionEdge of pkg.revisions) {
        const revision = revisionEdge.node
        const formDataResult = base64ToDomain(revision.formDataProto)

        if (formDataResult instanceof Error) {
            const err =
                new Error(`useFetchHealthPlanPackageWrapper: proto decoding error. ID:
                ${pkg.id}. Error message: ${formDataResult}`)
            console.error('Error decoding revision', revision, err)
            return {
                status: 'ERROR',
                error: formDataResult,
            }
        }

        formDatas[revision.id] = formDataResult
    }

    const formDatasInOrder = pkg.revisions.map((rEdge) => {
        return formDatas[rEdge.node.id]
    })
    const documentDates = makeDateTableFromFormData(formDatasInOrder)
    const documentLists = makeDocumentListFromFormDatas(formDatasInOrder)

    return {
        ...result,
        formDatas,
        documentDates,
        documentLists,
    }
}

// This wraps our call to useFetchHealthPlanPackageQuery, parsing out the protobuf
// from the response, returning extra errors in the case that parsing goes wrong
function useFetchHealthPlanPackageWrapper(id: string): WrappedFetchResultType {
    const results = wrapApolloResult(
        useFetchHealthPlanPackageQuery({
            variables: {
                input: {
                    pkgID: id,
                },
            },
        })
    )
    const result = results.result

    if (result.status === 'SUCCESS') {
        const parsedResult = parseProtos(result)

        return {
            ...results,
            result: parsedResult,
        }
    }

    return {
        ...results,
        result: result,
    }
}

function useFetchHealthPlanPackageWithQuestionsWrapper(
    id: string,
    onCompleted?: QueryFunctionOptions['onCompleted']
): WrappedFetchResultWithQuestionsType {
    const results = wrapApolloResult(
        useFetchHealthPlanPackageWithQuestionsQuery({
            variables: {
                input: {
                    pkgID: id,
                },
            },
            onCompleted,
            fetchPolicy: 'cache-and-network',
        })
    )
    const result = results.result

    if (result.status === 'SUCCESS') {
        const parsedResult = parseProtos(result)

        return {
            ...results,
            result: parsedResult,
        }
    }

    return {
        ...results,
        result: result,
    }
}

export {
    useFetchHealthPlanPackageWrapper,
    useFetchHealthPlanPackageWithQuestionsWrapper,
}
