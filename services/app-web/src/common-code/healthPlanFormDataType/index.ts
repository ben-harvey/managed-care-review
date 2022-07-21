// TEMPORARY: these files are embedded in app-web for now b/c
// CRA prevents you from importing code outside of /src
// The fix is to use yarn workspaces to allow us to import shared packages
// Domain Types
export type {
    ActuarialFirmType,
    ActuaryCommunicationType,
    ActuaryContact,
    ContractAmendmentInfo,
    ContractExecutionStatus,
    ContractType,
    DocumentCategoryType,
    UnlockedHealthPlanFormDataType,
    FederalAuthority,
    ManagedCareEntity,
    RateType,
    RateCapitationType,
    StateContact,
    SubmissionDocument,
    SubmissionType,
    RateDataType,
    CalendarDate,
} from './UnlockedHealthPlanFormDataType'

export type { ModifiedProvisions } from './ModifiedProvisions'

export { modifiedProvisionKeys } from './ModifiedProvisions'

export type { LockedHealthPlanFormDataType } from './LockedHealthPlanFormDataType'
export {
    hasValidContract,
    hasValidDocuments,
    hasValidRates,
    hasValidSupportingDocumentCategories,
    isContractAndRates,
    isContractOnly,
    isUnlockedHealthPlanFormData,
    isLockedHealthPlanFormData,
    programNames,
    packageName,
    generateRateName,
} from './healthPlanFormData'

export type { HealthPlanFormDataType } from './HealthPlanFormDataType'
export type { ProgramArgType } from './healthPlanFormData'
