import {
    UnlockedHealthPlanFormDataType,
    packageName as generatePackageName,
} from '../../../../app-web/src/common-code/healthPlanFormDataType'
import { formatCalendarDate } from '../../../../app-web/src/common-code/dateHelpers'
import {
    renderTemplate,
    stripHTMLFromTemplate,
    findPackagePrograms,
} from '../templateHelpers'
import type { EmailData, EmailConfiguration } from '../'
import { ProgramType, UpdateInfoType } from '../../domain-models'
import { reviewAndSubmitURL } from '../generateURLs'
import { pruneDuplicateEmails } from '../formatters'

export const unlockPackageStateEmail = async (
    formData: UnlockedHealthPlanFormDataType,
    updateInfo: UpdateInfoType,
    config: EmailConfiguration,
    statePrograms: ProgramType[],
    submitterEmails: string[]
): Promise<EmailData | Error> => {
    const isTestEnvironment = config.stage !== 'prod'
    const stateContactEmails = formData.stateContacts.map(
        (contact) => contact.email
    )
    const receiverEmails = pruneDuplicateEmails([
        ...stateContactEmails,
        ...submitterEmails,
        ...config.devReviewTeamEmails,
    ])

    //This checks to make sure all programs contained in submission exists for the state.
    const packagePrograms = findPackagePrograms(formData, statePrograms)

    if (packagePrograms instanceof Error) {
        return packagePrograms
    }

    const packageName = generatePackageName(formData, packagePrograms)

    const isContractAndRates =
        formData.submissionType === 'CONTRACT_AND_RATES' &&
        Boolean(formData.rateInfos.length)

    const packageURL = reviewAndSubmitURL(formData.id, config.baseUrl)

    const data = {
        packageName,
        unlockedBy: updateInfo.updatedBy,
        unlockedOn: formatCalendarDate(updateInfo.updatedAt),
        unlockedReason: updateInfo.updatedReason,
        shouldIncludeRates: formData.submissionType === 'CONTRACT_AND_RATES',
        rateInfos:
            isContractAndRates &&
            formData.rateInfos.map((rate) => ({
                rateName: rate.rateCertificationName,
            })),
        submissionURL: packageURL,
    }

    const result = await renderTemplate<typeof data>(
        'unlockPackageStateEmail',
        data
    )
    if (result instanceof Error) {
        return result
    } else {
        return {
            toAddresses: receiverEmails,
            sourceEmail: config.emailSource,
            subject: `${
                isTestEnvironment ? `[${config.stage}] ` : ''
            }${packageName} was unlocked by CMS`,
            bodyText: stripHTMLFromTemplate(result),
            bodyHTML: result,
        }
    }
}
