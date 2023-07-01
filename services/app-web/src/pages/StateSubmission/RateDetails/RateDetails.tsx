import React, { useEffect, useState, useRef } from 'react'
import { Form as UswdsForm } from '@trussworks/react-uswds'
import { FieldArray, FieldArrayRenderProps, Formik, FormikErrors } from 'formik'
import { useNavigate } from 'react-router-dom'
import { v4 as uuidv4 } from 'uuid'

import styles from '../StateSubmissionForm.module.scss'

import { RateInfoType } from '../../../common-code/healthPlanFormDataType'

import { ErrorSummary } from '../../../components'
import { formatFormDateForDomain } from '../../../formHelpers'
import { RateDetailsFormSchema } from './RateDetailsSchema'
import { PageActions } from '../PageActions'
import type { HealthPlanFormPageProps } from '../StateSubmissionForm'
import { useFocus } from '../../../hooks'

import { featureFlags } from '../../../common-code/featureFlags'
import { useLDClient } from 'launchdarkly-react-client-sdk'
import {
    formatActuaryContactsForForm,
    formatDocumentsForDomain,
    formatDocumentsForForm,
    formatForForm,
} from '../../../formHelpers/formatters'
import {
    RateCertFormType,
    SingleRateCert,
} from './SingleRateCert/SingleRateCert'
import { useS3 } from '../../../contexts/S3Context'
import { S3ClientT } from '../../../s3'
import { isLoadingOrHasFileErrors } from '../../../components/FileUpload'

// This function is used to get initial form values as well return empty form values when we add a new rate or delete a rate
// We need to include the getKey function in params because there are no guarantees currently file is in s3 even if when we load data from API
const generateRateCertFormValues = (params?: {
    rateInfo: RateInfoType
    getKey: S3ClientT['getKey']
}): RateCertFormType => {
    const rateInfo = params?.rateInfo

    return {
        id: rateInfo?.id ?? uuidv4(),
        key: uuidv4(),
        rateType: rateInfo?.rateType,
        rateCapitationType: rateInfo?.rateCapitationType,
        rateDateStart: formatForForm(rateInfo?.rateDateStart),
        rateDateEnd: formatForForm(rateInfo?.rateDateEnd),
        rateDateCertified: formatForForm(rateInfo?.rateDateCertified),
        effectiveDateStart: formatForForm(
            rateInfo?.rateAmendmentInfo?.effectiveDateStart
        ),
        effectiveDateEnd: formatForForm(
            rateInfo?.rateAmendmentInfo?.effectiveDateEnd
        ),
        rateProgramIDs: rateInfo?.rateProgramIDs ?? [],
        rateDocuments: params
            ? formatDocumentsForForm({
                  documents: rateInfo?.rateDocuments,
                  getKey: params.getKey,
              })
            : [],
        supportingDocuments: params
            ? formatDocumentsForForm({
                  documents: rateInfo?.supportingDocuments,
                  getKey: params.getKey,
              })
            : [],
        actuaryContacts: formatActuaryContactsForForm(
            rateInfo?.actuaryContacts
        ),
        actuaryCommunicationPreference:
            rateInfo?.actuaryCommunicationPreference,
        packagesWithSharedRateCerts:
            rateInfo?.packagesWithSharedRateCerts ?? [],
        hasSharedRateCert:
            rateInfo?.packagesWithSharedRateCerts === undefined
                ? undefined
                : (rateInfo?.packagesWithSharedRateCerts &&
                      rateInfo?.packagesWithSharedRateCerts.length) >= 1
                ? 'YES'
                : 'NO',
    }
}

interface RateInfoArrayType {
    rateInfos: RateCertFormType[]
}

export const rateErrorHandling = (
    error: string | FormikErrors<RateCertFormType> | undefined
): FormikErrors<RateCertFormType> | undefined => {
    if (typeof error === 'string') {
        return undefined
    }
    return error
}

export const RateDetails = ({
    draftSubmission,
    showValidations = false,
    previousDocuments,
    updateDraft,
}: HealthPlanFormPageProps): React.ReactElement => {
    const navigate = useNavigate()
    const { getKey } = useS3()

    // feature flags state management
    const ldClient = useLDClient()
    const showPackagesWithSharedRatesDropdown: boolean = ldClient?.variation(
        featureFlags.PACKAGES_WITH_SHARED_RATES.flag,
        featureFlags.PACKAGES_WITH_SHARED_RATES.defaultValue
    )
    const supportingDocsByRate = ldClient?.variation(
        featureFlags.SUPPORTING_DOCS_BY_RATE.flag,
        featureFlags.SUPPORTING_DOCS_BY_RATE.defaultValue
    )

    // form validation state management
    const [focusErrorSummaryHeading, setFocusErrorSummaryHeading] =
        useState(false)
    const errorSummaryHeadingRef = useRef<HTMLHeadingElement>(null)
    const [shouldValidate, setShouldValidate] = useState(showValidations)

    useEffect(() => {
        // Focus the error summary heading only if we are displaying
        // validation errors and the heading element exists
        if (focusErrorSummaryHeading && errorSummaryHeadingRef.current) {
            errorSummaryHeadingRef.current.focus()
        }
        setFocusErrorSummaryHeading(false)
    }, [focusErrorSummaryHeading])

    // multi-rates state management
    const [focusNewRate, setFocusNewRate] = useState(false)
    const newRateNameRef = useRef<HTMLElement | null>(null)
    const [newRateButtonRef, setNewRateButtonFocus] = useFocus() // This ref.current is always the same element

    const rateDetailsFormSchema = RateDetailsFormSchema({
        'packages-with-shared-rates': showPackagesWithSharedRatesDropdown,
        'supporting-docs-by-rate': supportingDocsByRate,
    })

    useEffect(() => {
        if (focusNewRate) {
            const legends = document.querySelectorAll('legend[tabindex="-1"]')
            const lastLegend = legends[legends.length - 1] as HTMLElement
            lastLegend.focus()

            // newRateNameRef?.current?.focus()
            // setFocusNewRate(false)
            // newRateNameRef.current = null
        }
    }, [focusNewRate])

    const rateInfosInitialValues: RateInfoArrayType = {
        rateInfos:
            draftSubmission.rateInfos.length > 0
                ? draftSubmission.rateInfos.map((rateInfo) =>
                      generateRateCertFormValues({ rateInfo, getKey })
                  )
                : [generateRateCertFormValues()],
    }

    const handleFormSubmit = async (
        form: RateInfoArrayType,
        setSubmitting: (isSubmitting: boolean) => void, // formik setSubmitting
        options: {
            shouldValidateDocuments: boolean
            redirectPath: string
        }
    ) => {
        const { rateInfos } = form
        if (options.shouldValidateDocuments) {
            const fileErrorsNeedAttention = rateInfos.some((rateInfo) =>
                isLoadingOrHasFileErrors(
                    rateInfo.supportingDocuments.concat(rateInfo.rateDocuments)
                )
            )
            if (fileErrorsNeedAttention) {
                // make inline field errors visible so user can correct documents, direct user focus to errors, and manually exit formik submit
                setShouldValidate(true)
                setFocusErrorSummaryHeading(true)
                setSubmitting(false)
                return
            }
        }

        const cleanedRateInfos = rateInfos.map((rateInfo) => {
            return {
                rateType: rateInfo.rateType,
                rateCapitationType: rateInfo.rateCapitationType,
                rateDocuments: formatDocumentsForDomain(
                    rateInfo.rateDocuments,
                    ['RATES']
                ),
                supportingDocuments: formatDocumentsForDomain(
                    rateInfo.supportingDocuments,
                    ['RATES_RELATED']
                ),
                rateDateStart: formatFormDateForDomain(rateInfo.rateDateStart),
                rateDateEnd: formatFormDateForDomain(rateInfo.rateDateEnd),
                rateDateCertified: formatFormDateForDomain(
                    rateInfo.rateDateCertified
                ),
                rateAmendmentInfo:
                    rateInfo.rateType === 'AMENDMENT'
                        ? {
                              effectiveDateStart: formatFormDateForDomain(
                                  rateInfo.effectiveDateStart
                              ),
                              effectiveDateEnd: formatFormDateForDomain(
                                  rateInfo.effectiveDateEnd
                              ),
                          }
                        : undefined,
                rateProgramIDs: rateInfo.rateProgramIDs,
                actuaryContacts: rateInfo.actuaryContacts,
                actuaryCommunicationPreference:
                    rateInfo.actuaryCommunicationPreference,
                packagesWithSharedRateCerts:
                    rateInfo.hasSharedRateCert === 'YES'
                        ? rateInfo.packagesWithSharedRateCerts
                        : [],
            }
        })

        draftSubmission.rateInfos = cleanedRateInfos

        try {
            const updatedSubmission = await updateDraft(draftSubmission)
            if (updatedSubmission instanceof Error) {
                setSubmitting(false)
                console.info(
                    'Error updating draft submission: ',
                    updatedSubmission
                )
            } else if (updatedSubmission) {
                navigate(options.redirectPath)
            }
        } catch (serverError) {
            setSubmitting(false)
        }
    }

    // Due to multi-rates we have extra handling around how error summary apperas
    // Error summary object keys will be used as DOM focus point from error-summary. Must be valid html selector
    // Error summary object values will be used as messages displays in error summary
    const generateErrorSummaryErrors = (
        errors: FormikErrors<RateInfoArrayType>
    ) => {
        const rateErrors = errors.rateInfos
        const errorObject: { [field: string]: string } = {}

        if (rateErrors && Array.isArray(rateErrors)) {
            rateErrors.forEach((rateError, index) => {
                if (!rateError) return

                Object.entries(rateError).forEach(([field, value]) => {
                    if (typeof value === 'string') {
                        //rateProgramIDs error message needs a # proceeding the key name because this is the only way to be able to link to the Select component element see comments in ErrorSummaryMessage component.
                        const errorKey =
                            field === 'rateProgramIDs' ||
                            field === 'packagesWithSharedRateCerts'
                                ? `#rateInfos.${index}.${field}`
                                : `rateInfos.${index}.${field}`
                        errorObject[errorKey] = value
                    }
                    // If the field is actuaryContacts then the value should be an array with at least one object of errors
                    if (
                        field === 'actuaryContacts' &&
                        Array.isArray(value) &&
                        Array.length > 0
                    ) {
                        //Currently, rate certifications only have 1 actuary contact
                        const actuaryContact = value[0]
                        Object.entries(actuaryContact).forEach(
                            ([contactField, contactValue]) => {
                                if (typeof contactValue === 'string') {
                                    const errorKey = `rateInfos.${index}.actuaryContacts.0.${contactField}`
                                    errorObject[errorKey] = contactValue
                                }
                            }
                        )
                    }
                })
            })
        }

        return errorObject
    }

    return (
        <Formik
            initialValues={rateInfosInitialValues}
            onSubmit={({ rateInfos }, { setSubmitting }) => {
                return handleFormSubmit({ rateInfos }, setSubmitting, {
                    shouldValidateDocuments: true,
                    redirectPath: `../contacts`,
                })
            }}
            validationSchema={rateDetailsFormSchema}
        >
            {({
                values: { rateInfos },
                errors,
                dirty,
                handleSubmit,
                isSubmitting,
                setSubmitting,
            }) => {
                return (
                    <>
                        <UswdsForm
                            className={styles.formContainer}
                            id="RateDetailsForm"
                            aria-label="Rate Details Form"
                            aria-describedby="form-guidance"
                            onSubmit={(e) => {
                                setShouldValidate(true)
                                setFocusErrorSummaryHeading(true)
                                handleSubmit(e)
                            }}
                        >
                            <fieldset className="usa-fieldset">
                                <legend className="srOnly">Rate Details</legend>
                                <span id="form-guidance">
                                    All fields are required
                                </span>

                                {shouldValidate && (
                                    <ErrorSummary
                                        errors={generateErrorSummaryErrors(
                                            errors
                                        )}
                                        headingRef={errorSummaryHeadingRef}
                                    />
                                )}
                                <FieldArray name="rateInfos">
                                    {({
                                        remove,
                                        push,
                                    }: FieldArrayRenderProps) => (
                                        <>
                                            {rateInfos.map(
                                                (rateInfo, index) => (
                                                    <SingleRateCert
                                                        key={rateInfo.key}
                                                        rateInfo={rateInfo}
                                                        index={index}
                                                        shouldValidate={
                                                            shouldValidate
                                                        }
                                                        parentSubmissionID={
                                                            draftSubmission.id
                                                        }
                                                        previousDocuments={
                                                            previousDocuments
                                                        }
                                                        multiRatesConfig={{
                                                            removeSelf: () => {
                                                                remove(index)
                                                                setNewRateButtonFocus()
                                                            },
                                                            reassignNewRateRef:
                                                                (el) =>
                                                                    (newRateNameRef.current =
                                                                        el),
                                                        }}
                                                    />
                                                )
                                            )}
                                            <button
                                                type="button"
                                                className={`usa-button usa-button--outline ${styles.addContactBtn}`}
                                                onClick={() => {
                                                    const newRate =
                                                        generateRateCertFormValues()
                                                    push(newRate)
                                                    setFocusNewRate(true)
                                                }}
                                                ref={newRateButtonRef}
                                            >
                                                Add another rate certification
                                            </button>
                                        </>
                                    )}
                                </FieldArray>
                            </fieldset>
                            <PageActions
                                backOnClick={async () => {
                                    const redirectPath = `../contract-details`
                                    if (dirty) {
                                        await handleFormSubmit(
                                            { rateInfos },
                                            setSubmitting,
                                            {
                                                shouldValidateDocuments: false,
                                                redirectPath,
                                            }
                                        )
                                    } else {
                                        navigate(redirectPath)
                                    }
                                }}
                                saveAsDraftOnClick={async () => {
                                    await handleFormSubmit(
                                        { rateInfos },
                                        setSubmitting,
                                        {
                                            shouldValidateDocuments: true,
                                            redirectPath: '/dashboard',
                                        }
                                    )
                                }}
                                disableContinue={
                                    shouldValidate &&
                                    !!Object.keys(errors).length
                                }
                                actionInProgress={isSubmitting}
                            />
                        </UswdsForm>
                    </>
                )
            }}
        </Formik>
    )
}
