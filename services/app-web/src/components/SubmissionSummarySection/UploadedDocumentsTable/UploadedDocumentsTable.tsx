import { Link, Tag } from '@trussworks/react-uswds'
import { useEffect, useState } from 'react'
import { NavLink } from 'react-router-dom'
import dayjs from 'dayjs'
import { useS3 } from '../../../contexts/S3Context'
import { SubmissionDocument } from '../../../common-code/healthPlanFormDataType'
import { DocumentDateLookupTable } from '../../../pages/SubmissionSummary/SubmissionSummary'
import styles from './UploadedDocumentsTable.module.scss'
import { usePreviousSubmission } from '../../../hooks'
import { SharedRateCertDisplay } from '../../../common-code/healthPlanFormDataType/UnlockedHealthPlanFormDataType'

export type UploadedDocumentsTableProps = {
    documents: SubmissionDocument[]
    caption: string | null
    documentCategory: string
    documentDateLookupTable?: DocumentDateLookupTable
    packagesWithSharedRateCerts?: SharedRateCertDisplay[]
    isSupportingDocuments?: boolean
    isEditing?: boolean
    isCMSUser?: boolean
}

type DocumentWithLink = { url: string | null } & SubmissionDocument

const isBothContractAndRateSupporting = (doc: SubmissionDocument) =>
    doc.documentCategories.includes('CONTRACT_RELATED') &&
    doc.documentCategories.includes('RATES_RELATED')

export const UploadedDocumentsTable = ({
    documents,
    caption,
    documentCategory,
    documentDateLookupTable,
    packagesWithSharedRateCerts,
    isSupportingDocuments = false,
    isEditing = false,
    isCMSUser,
}: UploadedDocumentsTableProps): React.ReactElement => {
    const { getURL, getKey } = useS3()
    const [refreshedDocs, setRefreshedDocs] = useState<DocumentWithLink[]>([])
    const shouldShowEditButton = isEditing && isSupportingDocuments
    const shouldShowAsteriskExplainer = refreshedDocs.some((doc) =>
        isBothContractAndRateSupporting(doc)
    )
    const shouldHaveNewTag = (doc: DocumentWithLink) => {
        return (
            isCMSUser &&
            documentDateLookupTable &&
            documentDateLookupTable[doc.name] >
                documentDateLookupTable.previousSubmissionDate
        )
    }
    const hasSharedRateCert =
        (packagesWithSharedRateCerts &&
            packagesWithSharedRateCerts.length > 0) ||
        false
    const isPreviousSubmission = usePreviousSubmission()
    const showSharedInfo = hasSharedRateCert && !isPreviousSubmission
    const borderTopGradientStyles = `borderTopLinearGradient ${styles.uploadedDocumentsTable}`
    const supportingDocsTopMarginStyles = isSupportingDocuments
        ? styles.withMarginTop
        : ''

    const linkedPackageIsDraft = (packageName?: string) =>
        packageName && packageName.includes('(Draft)')

    const tableCaptionJSX = (
        <>
            <span>{caption}</span>
            {shouldShowEditButton && (
                <Link
                    variant="unstyled"
                    asCustom={NavLink}
                    className="usa-button usa-button--outline"
                    to="../documents"
                >
                    Edit <span className="srOnly">{caption}</span>
                </Link>
            )}
        </>
    )

    useEffect(() => {
        const refreshDocuments = async () => {
            const newDocuments = await Promise.all(
                documents.map(async (doc) => {
                    const key = getKey(doc.s3URL)
                    if (!key)
                        return {
                            ...doc,
                            url: null,
                        }

                    const documentLink = await getURL(key)
                    return {
                        ...doc,
                        url: documentLink,
                    }
                })
            ).catch((err) => {
                console.log(err)
                return []
            })
            setRefreshedDocs(newDocuments)
        }

        void refreshDocuments()
    }, [documents, getKey, getURL])

    // Empty State
    if (refreshedDocs.length === 0) {
        return (
            <div className={supportingDocsTopMarginStyles}>
                <b className={styles.captionContainer}>{tableCaptionJSX}</b>
                <p
                    className={`${borderTopGradientStyles} ${styles.supportingDocsEmpty}`}
                >
                    {isSupportingDocuments
                        ? 'No supporting documents'
                        : 'No documents'}
                </p>
            </div>
        )
    }
    return (
        <>
            <table
                className={`${borderTopGradientStyles} ${supportingDocsTopMarginStyles}`}
            >
                <caption className="text-bold">
                    <div className={styles.captionContainer}>
                        {tableCaptionJSX}
                    </div>
                </caption>
                <thead>
                    <tr>
                        <th scope="col">Document name</th>
                        <th scope="col">Date added</th>
                        <th scope="col">Document category</th>
                        {showSharedInfo && (
                            <th scope="col">Linked submissions</th>
                        )}
                    </tr>
                </thead>
                <tbody>
                    {refreshedDocs.map((doc) => (
                        <tr key={doc.name}>
                            {doc.url ? (
                                <td>
                                    {shouldHaveNewTag(doc) ? (
                                        <Tag className={styles.newDocTag}>
                                            NEW
                                        </Tag>
                                    ) : null}
                                    {showSharedInfo ? (
                                        <Tag className={styles.sharedDocTag}>
                                            SHARED
                                        </Tag>
                                    ) : null}
                                    <Link
                                        aria-label={`${doc.name} (opens in new window)`}
                                        href={doc.url}
                                        variant="external"
                                        target="_blank"
                                    >
                                        {isSupportingDocuments &&
                                        isBothContractAndRateSupporting(doc)
                                            ? `*${doc.name}`
                                            : doc.name}
                                    </Link>
                                </td>
                            ) : (
                                <td>
                                    {shouldHaveNewTag(doc) ? (
                                        <Tag className={styles.newDocTag}>
                                            NEW
                                        </Tag>
                                    ) : null}{' '}
                                    {doc.name}
                                </td>
                            )}
                            <td>
                                {documentDateLookupTable
                                    ? dayjs(
                                          documentDateLookupTable[doc.name]
                                      ).format('M/D/YY')
                                    : ''}
                            </td>
                            <td>{documentCategory}</td>
                            {showSharedInfo
                                ? packagesWithSharedRateCerts &&
                                  packagesWithSharedRateCerts.map((item) => (
                                      <td key={item.packageName}>
                                          {isCMSUser &&
                                          linkedPackageIsDraft(
                                              item.packageName
                                          ) ? (
                                              <span>{item.packageName}</span>
                                          ) : (
                                              <NavLink
                                                  to={`/submissions/${item.packageId}`}
                                              >
                                                  {item.packageName}
                                              </NavLink>
                                          )}
                                      </td>
                                  ))
                                : null}
                        </tr>
                    ))}
                </tbody>
            </table>
            {shouldShowAsteriskExplainer && (
                <span>
                    * Listed as both a contract and rate supporting document
                </span>
            )}
        </>
    )
}
