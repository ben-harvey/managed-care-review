import {
    Form as UswdsForm,
    Fieldset,
    FormGroup,
    Link,
    Label,
} from '@trussworks/react-uswds'
import { Field, Formik, FormikErrors, FormikHelpers } from 'formik'
import React, { useEffect } from 'react'
import { Link as ReactRouterLink, useHistory } from 'react-router-dom'
import Select, { AriaOnFocus } from 'react-select'
import * as Yup from 'yup'
import {
    ErrorSummary,
    FieldRadio,
    FieldTextarea,
    PoliteErrorMessage,
} from '../../../components'
import { SubmissionTypeRecord } from '../../../constants/submissions'
import { useAuth } from '../../../contexts/AuthContext'
import {
    CreateDraftSubmissionInput,
    Program,
    Submission2,
    SubmissionType as SubmissionTypeT,
    useCreateSubmission2Mutation,
} from '../../../gen/gqlClient'
import { PageActions } from '../PageActions'
import styles from '../StateSubmissionForm.module.scss'
import { GenericApiErrorBanner } from '../../../components/Banner/GenericApiErrorBanner/GenericApiErrorBanner'
import { DraftSubmissionType } from '../../../common-code/domain-models'

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
    draftSubmission?: DraftSubmissionType
    updateDraft?: (input: DraftSubmissionType) => Promise<Submission2 | Error>
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

    const [createDraftSubmission, { error }] = useCreateSubmission2Mutation({
        // An alternative to messing with the cache like we do with create, just zero it out.
        update(cache, { data }) {
            if (data) {
                cache.modify({
                    id: 'ROOT_QUERY',
                    fields: {
                        indexSubmissions2(_index, { DELETE }) {
                            return DELETE
                        },
                    },
                })
            }
        },
    })

    useEffect(() => {
        // Focus the error summary heading only if we are displaying
        // validation errors and the heading element exists
        if (focusErrorSummaryHeading && errorSummaryHeadingRef.current) {
            errorSummaryHeadingRef.current.focus()
        }
        setFocusErrorSummaryHeading(false)
    }, [focusErrorSummaryHeading])

    if (error && !showFormAlert) {
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

                const draftSubmission: Submission2 | undefined =
                    result?.data?.createSubmission2.submission

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

            // set new values
            draftSubmission.programIDs = values.programIDs
            draftSubmission.submissionType =
                values.submissionType as SubmissionTypeT
            draftSubmission.submissionDescription = values.submissionDescription

            try {
                await updateDraft(draftSubmission)

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
                            {showFormAlert && <GenericApiErrorBanner />}
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
                                <Label htmlFor="programIDs">Programs</Label>
                                {showFieldErrors(errors.programIDs) && (
                                    <PoliteErrorMessage>
                                        {errors.programIDs}
                                    </PoliteErrorMessage>
                                )}
                                <Field name="programIDs">
                                    {/* eslint-disable-next-line @typescript-eslint/ban-ts-comment */}
                                    {/* @ts-ignore */}
                                    {({ form }) => (
                                        <Select
                                            defaultValue={values.programIDs.map(
                                                (programID) => {
                                                    const program =
                                                        programs.find(
                                                            (p) =>
                                                                p.id ===
                                                                programID
                                                        )
                                                    if (!program) {
                                                        return {
                                                            value: programID,
                                                            label: 'Unknown Program',
                                                        }
                                                    }
                                                    return {
                                                        value: program.id,
                                                        label: program.name,
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
                                    role="radiogroup"
                                    aria-required
                                    legend="Submission type"
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
                                aria-describedby="submissionDescriptionHelp"
                                showError={showFieldErrors(
                                    errors.submissionDescription
                                )}
                                hint={
                                    <>
                                        <p id="submissionDescriptionHelp">
                                            Provide a 1-2 paragraph summary of
                                            your submission that highlights any
                                            important changes CMS reviewers will
                                            need to be aware of
                                        </p>
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
