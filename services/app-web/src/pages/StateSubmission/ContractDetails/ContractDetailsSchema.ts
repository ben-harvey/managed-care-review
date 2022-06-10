import * as Yup from 'yup'
import dayjs from 'dayjs'
import { validateDateFormat } from '../../../formHelpers'

Yup.addMethod(Yup.date, 'validateDateFormat', validateDateFormat)

const yesNoError = Yup.string().when('contractType', {
    is: 'AMENDMENT',
    then: Yup.string().defined('You must select yes or no'),
})

// Formik setup
export const ContractDetailsFormSchema = Yup.object().shape({
    contractType: Yup.string().defined(
        'You must choose a contract action type'
    ),
    contractExecutionStatus: Yup.string().defined(
        'You must select a contract status'
    ),
    contractDateStart: Yup.date().when('contractType', (contractType) => {
        if (contractType) {
            return (
                Yup.date()
                    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
                    // @ts-ignore-next-line
                    .validateDateFormat('YYYY-MM-DD', true)
                    .defined('You must enter a start date')
                    .typeError('The start date must be in MM/DD/YYYY format')
            )
        }
    }),
    contractDateEnd: Yup.date().when('contractType', (contractType) => {
        if (contractType) {
            return (
                Yup.date()
                    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
                    // @ts-ignore-next-line
                    .validateDateFormat('YYYY-MM-DD', true)
                    .defined('You must enter an end date')
                    .typeError('The end date must be in MM/DD/YYYY format')
                    .when(
                        // ContractDateEnd must be at minimum the day after Start
                        'contractDateStart',
                        (contractDateStart: Date, schema: Yup.DateSchema) => {
                            const startDate = dayjs(contractDateStart)
                            if (startDate.isValid()) {
                                return schema.min(
                                    startDate.add(1, 'day'),
                                    'The end date must come after the start date'
                                )
                            }
                        }
                    )
            )
        }
    }),
    managedCareEntities: Yup.array().when('contractType', {
        is: (contractType: string | undefined) => contractType,
        then: Yup.array().min(1, 'You must select at least one entity'),
    }),
    federalAuthorities: Yup.array().when('contractType', {
        is: (contractType: string | undefined) => contractType,
        then: Yup.array().min(1, 'You must select at least one authority'),
    }),

    modifiedBenefitsProvided: yesNoError,
    modifiedGeoAreaServed: yesNoError,
    modifiedMedicaidBeneficiaries: yesNoError,
    modifiedRiskSharingStrategy: yesNoError,
    modifiedIncentiveArrangements: yesNoError,
    modifiedWitholdAgreements: yesNoError,
    modifiedStateDirectedPayments: yesNoError,
    modifiedPassThroughPayments: yesNoError,
    modifiedPaymentsForMentalDiseaseInstitutions: yesNoError,
    modifiedMedicalLossRatioStandards: yesNoError,
    modifiedOtherFinancialPaymentIncentive: yesNoError,
    modifiedEnrollmentProcess: yesNoError,
    modifiedGrevienceAndAppeal: yesNoError,
    modifiedNetworkAdequacyStandards: yesNoError,
    modifiedLengthOfContract: yesNoError,
    modifiedNonRiskPaymentArrangements: yesNoError,
})
