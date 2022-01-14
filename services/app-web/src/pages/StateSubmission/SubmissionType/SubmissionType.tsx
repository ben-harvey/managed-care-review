import React, { useEffect } from 'react'
import * as Yup from 'yup'
import {
    Alert,
    Form as UswdsForm,
    Fieldset,
    FormGroup,
    Link,
    Label,
} from '@trussworks/react-uswds'
import { Formik, FormikHelpers, FormikErrors, Field } from 'formik'
import { useHistory, Link as ReactRouterLink } from 'react-router-dom'
import Select, { AriaOnFocus } from 'react-select'

import {
    CreateDraftSubmissionInput,
    DraftSubmission,
    SubmissionType as SubmissionTypeT,
    useCreateDraftSubmissionMutation,
    UpdateDraftSubmissionInput,
    Program,
} from '../../../gen/gqlClient'

import styles from '../StateSubmissionForm.module.scss'

import { useAuth } from '../../../contexts/AuthContext'
import {
    ErrorSummary,
    FieldTextarea,
    FieldRadio,
    PoliteErrorMessage,
} from '../../../components'
import { SubmissionTypeRecord } from '../../../constants/submissions'
import {
    cleanDraftSubmission,
    updatesFromSubmission,
} from '../updateSubmissionTransform'
import { PageActions } from '../PageActions'

// Formik setup
// Should be listed in order of appearance on field to allow errors to focus as expected
const SubmissionTypeFormSchema = Yup.object().shape({
    programIDs: Yup.array().min(1, 'You must select at least one program'),
    submissionType: Yup.string().required('You must choose a submission type'),
    submissionDescription: Yup.string().required(
        'You must provide a description of any major changes or updates'
    ),
})
export interface SubmissionTypeFormValues {
    programIDs: string[]
    submissionDescription: string
    submissionType: string
}
type SubmissionTypeProps = {
    showValidations?: boolean
    draftSubmission?: DraftSubmission
    updateDraft?: (
        input: UpdateDraftSubmissionInput
    ) => Promise<DraftSubmission | undefined>
    formAlert?: React.ReactElement
}

interface ProgramOption {
    readonly value: string
    readonly label: string
    readonly isFixed?: boolean
    readonly isDisabled?: boolean
}

type FormError =
    FormikErrors<SubmissionTypeFormValues>[keyof FormikErrors<SubmissionTypeFormValues>]
export const SubmissionType = ({
    showValidations = false,
    draftSubmission,
    updateDraft,
    formAlert,
}: SubmissionTypeProps): React.ReactElement => {
    const [showFormAlert, setShowFormAlert] = React.useState(false)
    const [shouldValidate, setShouldValidate] = React.useState(showValidations)
    const { loggedInUser } = useAuth()
    const errorSummaryHeadingRef = React.useRef<HTMLHeadingElement>(null)
    const [focusErrorSummaryHeading, setFocusErrorSummaryHeading] =
        React.useState(false)

    let programs: Program[] = []
    if (loggedInUser && loggedInUser.__typename === 'StateUser') {
        programs = loggedInUser.state.programs
    }

    const history = useHistory()
    const location = history.location
    const isNewSubmission = location.pathname === '/submissions/new'

    const programOptions: Array<{ value: string; label: string }> =
        programs.map((program) => {
            return { value: program.id, label: program.name }
        })

    const onFocus: AriaOnFocus<ProgramOption> = ({ focused, isDisabled }) => {
        const msg = `You are currently focused on option ${focused.label}${
            isDisabled ? ', disabled' : ''
        }`
        return msg
    }

    const [createDraftSubmission, { error }] = useCreateDraftSubmissionMutation(
        {
            // This function updates the Apollo Client Cache after we create a new DraftSubmission
            // Without it, we wouldn't show this newly created submission on the dashboard page
            // without a refresh. Anytime a mutation does more than "modify an existing object"
            // you'll need to handle the cache.
            update(cache, { data }) {
                if (data) {
                    cache.modify({
                        fields: {
                            indexSubmissions(
                                index = { totalCount: 0, edges: [] }
                            ) {
                                const newID = cache.identify(
                                    data.createDraftSubmission.draftSubmission
                                )
                                // This isn't quite what is documented, but it's clear this
                                // is how things work from looking at the dev-tools
                                const newRef = { __ref: newID }

                                return {
                                    totalCount: index.totalCount + 1,
                                    edges: [
                                        {
                                            node: newRef,
                                        },
                                        ...index.edges,
                                    ],
                                }
                            },
                        },
                    })
                }
            },
        }
    )

    useEffect(() => {
        // Focus the error summary heading only if we are displaying
        // validation errors and the heading element exists
        if (focusErrorSummaryHeading && errorSummaryHeadingRef.current) {
            errorSummaryHeadingRef.current.focus()
        }
        setFocusErrorSummaryHeading(false)
    }, [focusErrorSummaryHeading])

    if ((error || formAlert) && !showFormAlert) {
        setShowFormAlert(true)
    }

    const showFieldErrors = (error?: FormError) =>
        shouldValidate && Boolean(error)

    const submissionTypeInitialValues: SubmissionTypeFormValues = {
        programIDs: draftSubmission?.programIDs ?? [],
        submissionDescription: draftSubmission?.submissionDescription ?? '',
        submissionType: draftSubmission?.submissionType ?? '',
    }

    const handleFormSubmit = async (
        values: SubmissionTypeFormValues,
        formikHelpers: FormikHelpers<SubmissionTypeFormValues>
    ) => {
        if (isNewSubmission) {
            try {
                if (
                    !(
                        values.submissionType === 'CONTRACT_ONLY' ||
                        values.submissionType === 'CONTRACT_AND_RATES'
                    )
                ) {
                    console.log(
                        'unexpected error, attempting to submit a submissionType of ',
                        values.submissionType
                    )
                    return
                }

                const input: CreateDraftSubmissionInput = {
                    programIDs: values.programIDs,
                    submissionType: values.submissionType,
                    submissionDescription: values.submissionDescription,
                }

                const result = await createDraftSubmission({
                    variables: { input },
                })

                const draftSubmission: DraftSubmission | undefined =
                    result?.data?.createDraftSubmission.draftSubmission

                if (draftSubmission) {
                    history.push(
                        `/submissions/${draftSubmission.id}/contract-details`
                    )
                }
            } catch (serverError) {
                setShowFormAlert(true)
                formikHelpers.setSubmitting(false) // unblock submit button to allow resubmit
                console.log(
                    'Log: creating new submission failed with server error',
                    serverError
                )
            }
        } else {
            if (draftSubmission === undefined || !updateDraft) {
                console.log(draftSubmission, updateDraft)
                console.log(
                    'ERROR, SubmissionType for does not have props needed to update a draft.'
                )
                return
            }
            const updatedDraft = updatesFromSubmission(draftSubmission)

            updatedDraft.programIDs = values.programIDs
            updatedDraft.submissionType =
                values.submissionType as SubmissionTypeT
            updatedDraft.submissionDescription = values.submissionDescription

            const cleanSubmission = cleanDraftSubmission(updatedDraft)
            try {
                await updateDraft({
                    submissionID: draftSubmission.id,
                    draftSubmissionUpdates: cleanSubmission,
                })

                history.push(
                    `/submissions/${draftSubmission.id}/contract-details`
                )
            } catch (serverError) {
                setShowFormAlert(true)
                formikHelpers.setSubmitting(false) // unblock submit button to allow resubmit
            }
        }
    }

    return (
        <Formik
            initialValues={submissionTypeInitialValues}
            onSubmit={handleFormSubmit}
            validationSchema={SubmissionTypeFormSchema}
        >
            {({ values, errors, handleSubmit, isSubmitting }) => (
                <>
                    <UswdsForm
                        className={styles.formContainer}
                        id="SubmissionTypeForm"
                        aria-label={
                            isNewSubmission
                                ? 'New Submission Form'
                                : 'Submission Type Form'
                        }
                        aria-describedby="form-guidance"
                        onSubmit={handleSubmit}
                    >
                        <fieldset className="usa-fieldset">
                            <legend className="srOnly">Submission type</legend>
                            {showFormAlert &&
                                (formAlert || (
                                    <Alert type="error">
                                        Something went wrong
                                    </Alert>
                                ))}
                            <span id="form-guidance">
                                All fields are required
                            </span>

                            {shouldValidate && (
                                <ErrorSummary
                                    errors={errors}
                                    headingRef={errorSummaryHeadingRef}
                                />
                            )}

                            <FormGroup
                                error={showFieldErrors(errors.programIDs)}
                            >
                                <Label htmlFor="programIDs">Program(s)</Label>
                                {showFieldErrors(errors.programIDs) && (
                                    <PoliteErrorMessage>
                                        {errors.programIDs}
                                    </PoliteErrorMessage>
                                )}
                                <Field name="programIDs">
                                    {/* eslint-disable-next-line @typescript-eslint/ban-ts-comment */}
                                    {/* @ts-ignore */}
                                    {({ field, form }) => (
                                        <Select
                                            defaultValue={values.programIDs.map(
                                                (item) => {
                                                    return {
                                                        value: item,
                                                        label: item.toUpperCase(),
                                                    }
                                                }
                                            )}
                                            className={styles.multiSelect}
                                            classNamePrefix="program-select"
                                            id="programIDs"
                                            name="programIDs"
                                            aria-label="programs (required)"
                                            options={programOptions}
                                            isMulti
                                            ariaLiveMessages={{
                                                onFocus,
                                            }}
                                            onChange={(selectedOption) =>
                                                form.setFieldValue(
                                                    'programIDs',
                                                    selectedOption.map(
                                                        (item) => item.value
                                                    )
                                                )
                                            }
                                        />
                                    )}
                                </Field>
                            </FormGroup>
                            <FormGroup
                                error={showFieldErrors(errors.submissionType)}
                            >
                                <Fieldset
                                    className={styles.radioGroup}
                                    aria-required
                                    legend="Choose submission type"
                                >
                                    {showFieldErrors(errors.submissionType) && (
                                        <PoliteErrorMessage>
                                            {errors.submissionType}
                                        </PoliteErrorMessage>
                                    )}
                                    <FieldRadio
                                        checked={
                                            values.submissionType ===
                                            'CONTRACT_ONLY'
                                        }
                                        id="contractOnly"
                                        name="submissionType"
                                        label={
                                            SubmissionTypeRecord[
                                                'CONTRACT_ONLY'
                                            ]
                                        }
                                        value={'CONTRACT_ONLY'}
                                    />
                                    <FieldRadio
                                        checked={
                                            values.submissionType ===
                                            'CONTRACT_AND_RATES'
                                        }
                                        id="contractRate"
                                        name="submissionType"
                                        label={
                                            SubmissionTypeRecord[
                                                'CONTRACT_AND_RATES'
                                            ]
                                        }
                                        value={'CONTRACT_AND_RATES'}
                                    />
                                </Fieldset>
                            </FormGroup>
                            <FieldTextarea
                                label="Submission description"
                                id="submissionDescription"
                                name="submissionDescription"
                                aria-required
                                showError={showFieldErrors(
                                    errors.submissionDescription
                                )}
                                hint={
                                    <>
                                        <Link
                                            variant="external"
                                            asCustom={ReactRouterLink}
                                            to={{
                                                pathname: '/help',
                                                hash: '#submission-description',
                                            }}
                                            target="_blank"
                                        >
                                            View description examples
                                        </Link>

                                        <p>
                                            Provide a description of any major
                                            changes or updates
                                        </p>
                                    </>
                                }
                            />
                        </fieldset>
                        <PageActions
                            pageVariant="FIRST"
                            backOnClick={() => history.push('/dashboard')}
                            continueOnClick={() => {
                                setShouldValidate(true)
                                setFocusErrorSummaryHeading(true)
                            }}
                            saveAsDraftOnClick={() => setShouldValidate(true)}
                            continueDisabled={isSubmitting}
                        />
                    </UswdsForm>
                </>
            )}
        </Formik>
    )
}
