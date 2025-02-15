import SUBMIT_HEALTH_PLAN_PACKAGE from '../../../../app-graphql/src/mutations/submitHealthPlanPackage.graphql'
import {
    constructTestPostgresServer,
    createAndUpdateTestHealthPlanPackage,
    fetchTestHealthPlanPackageById,
    defaultContext,
    defaultFloridaProgram,
    unlockTestHealthPlanPackage,
    resubmitTestHealthPlanPackage,
    createAndSubmitTestHealthPlanPackage,
    defaultFloridaRateProgram,
    submitTestHealthPlanPackage,
} from '../../testHelpers/gqlHelpers'
import { testEmailConfig, testEmailer } from '../../testHelpers/emailerHelpers'
import { base64ToDomain } from '../../../../app-web/src/common-code/proto/healthPlanFormDataProto'
import {
    generateRateName,
    packageName,
} from '../../../../app-web/src/common-code/healthPlanFormDataType'
import { latestFormData } from '../../testHelpers/healthPlanPackageHelpers'
import {
    mockEmailParameterStoreError,
    getTestStateAnalystsEmails,
} from '../../testHelpers/parameterStoreHelpers'
import * as awsSESHelpers from '../../testHelpers/awsSESHelpers'
import { testLDService } from '../../testHelpers/launchDarklyHelpers'
import { testCMSUser, testStateUser } from '../../testHelpers/userHelpers'

describe('submitHealthPlanPackage', () => {
    const cmsUser = testCMSUser()
    it('returns a StateSubmission if complete', async () => {
        const server = await constructTestPostgresServer()

        // setup
        const initialPkg = await createAndUpdateTestHealthPlanPackage(
            server,
            {}
        )
        const draft = latestFormData(initialPkg)
        const draftID = draft.id

        await new Promise((resolve) => setTimeout(resolve, 2000))

        // submit
        const submitResult = await server.executeOperation({
            query: SUBMIT_HEALTH_PLAN_PACKAGE,
            variables: {
                input: {
                    pkgID: draftID,
                },
            },
        })

        expect(submitResult.errors).toBeUndefined()
        const createdID = submitResult?.data?.submitHealthPlanPackage.pkg.id

        // test result
        const pkg = await fetchTestHealthPlanPackageById(server, createdID)

        const resultDraft = latestFormData(pkg)

        // The submission fields should still be set
        expect(resultDraft.id).toEqual(createdID)
        expect(resultDraft.submissionType).toBe('CONTRACT_AND_RATES')
        expect(resultDraft.programIDs).toEqual([defaultFloridaProgram().id])
        // check that the stateNumber is being returned the same
        expect(resultDraft.stateNumber).toEqual(draft.stateNumber)
        expect(resultDraft.submissionDescription).toBe('An updated submission')
        expect(resultDraft.documents).toEqual(draft.documents)

        // Contract details fields should still be set
        expect(resultDraft.contractType).toEqual(draft.contractType)
        expect(resultDraft.contractExecutionStatus).toEqual(
            draft.contractExecutionStatus
        )
        expect(resultDraft.contractDateStart).toEqual(draft.contractDateStart)
        expect(resultDraft.contractDateEnd).toEqual(draft.contractDateEnd)
        expect(resultDraft.managedCareEntities).toEqual(
            draft.managedCareEntities
        )
        expect(resultDraft.contractDocuments).toEqual(draft.contractDocuments)

        expect(resultDraft.federalAuthorities).toEqual(draft.federalAuthorities)

        if (resultDraft.status == 'DRAFT') {
            throw new Error('Not a locked submission')
        }

        // submittedAt should be set to today's date
        const today = new Date()
        const expectedDate = today.toISOString().split('T')[0]
        expect(pkg.initiallySubmittedAt).toEqual(expectedDate)

        // UpdatedAt should be after the former updatedAt
        const resultUpdated = new Date(resultDraft.updatedAt)
        const createdUpdated = new Date(draft.updatedAt)
        expect(
            resultUpdated.getTime() - createdUpdated.getTime()
        ).toBeGreaterThan(0)
    }, 20000)

    it('returns an error if there are no contract documents attached', async () => {
        const server = await constructTestPostgresServer()

        const draft = await createAndUpdateTestHealthPlanPackage(server, {
            documents: [],
            contractDocuments: [],
        })
        const draftID = draft.id

        const submitResult = await server.executeOperation({
            query: SUBMIT_HEALTH_PLAN_PACKAGE,
            variables: {
                input: {
                    pkgID: draftID,
                },
            },
        })

        expect(submitResult.errors).toBeDefined()

        expect(submitResult.errors?.[0].extensions?.code).toBe('BAD_USER_INPUT')
        expect(submitResult.errors?.[0].extensions?.message).toBe(
            'formData must have valid documents'
        )
    })

    it('returns an error if the package is already SUBMITTED', async () => {
        const server = await constructTestPostgresServer()

        const draft = await createAndSubmitTestHealthPlanPackage(server)
        const draftID = draft.id

        const submitResult = await server.executeOperation({
            query: SUBMIT_HEALTH_PLAN_PACKAGE,
            variables: {
                input: {
                    pkgID: draftID,
                },
            },
        })

        expect(submitResult.errors).toBeDefined()

        expect(submitResult.errors?.[0].extensions).toEqual(
            expect.objectContaining({
                code: 'INTERNAL_SERVER_ERROR',
                cause: 'INVALID_PACKAGE_STATUS',
                exception: {
                    locations: undefined,
                    message:
                        'Attempted to submit an already submitted package.',
                    path: undefined,
                },
            })
        )

        expect(submitResult.errors?.[0].message).toBe(
            'Attempted to submit an already submitted package.'
        )
    })

    it('returns an error if there are no contract details fields', async () => {
        const server = await constructTestPostgresServer()

        const draft = await createAndUpdateTestHealthPlanPackage(server, {
            contractType: undefined,
            contractExecutionStatus: undefined,
            managedCareEntities: [],
            federalAuthorities: [],
        })

        const draftID = draft.id
        const submitResult = await server.executeOperation({
            query: SUBMIT_HEALTH_PLAN_PACKAGE,
            variables: {
                input: {
                    pkgID: draftID,
                },
            },
        })

        expect(submitResult.errors).toBeDefined()

        expect(submitResult.errors?.[0].extensions?.code).toBe('BAD_USER_INPUT')
        expect(submitResult.errors?.[0].extensions?.message).toBe(
            'formData is missing required contract fields'
        )
    })

    it('returns an error if there are missing rate details fields for submission type', async () => {
        const server = await constructTestPostgresServer()

        const draft = await createAndUpdateTestHealthPlanPackage(server, {
            submissionType: 'CONTRACT_AND_RATES',
            rateInfos: [
                {
                    rateType: 'NEW' as const,
                    rateDateStart: new Date(Date.UTC(2025, 5, 1)),
                    rateDateEnd: new Date(Date.UTC(2026, 4, 30)),
                    rateDateCertified: new Date(Date.UTC(2025, 3, 15)),
                    rateDocuments: [
                        {
                            name: 'rateDocument.pdf',
                            s3URL: 'fakeS3URL',
                            documentCategories: ['RATES' as const],
                        },
                    ],
                    supportingDocuments: [],
                    rateProgramIDs: ['3b8d8fa1-1fa6-4504-9c5b-ef522877fe1e'],
                    actuaryContacts: [
                        {
                            name: 'test name',
                            titleRole: 'test title',
                            email: 'email@example.com',
                            actuarialFirm: undefined,
                        },
                    ],
                    actuaryCommunicationPreference: 'OACT_TO_ACTUARY' as const,
                    packagesWithSharedRateCerts: [],
                },
            ],
        })

        const draftID = draft.id
        const submitResult = await server.executeOperation({
            query: SUBMIT_HEALTH_PLAN_PACKAGE,
            variables: {
                input: {
                    pkgID: draftID,
                },
            },
        })

        expect(submitResult.errors).toBeDefined()

        expect(submitResult.errors?.[0].extensions?.code).toBe('BAD_USER_INPUT')
        expect(submitResult.errors?.[0].extensions?.message).toBe(
            'formData is missing required rate fields'
        )
    })

    it('does not remove any rate data from CONTRACT_AND_RATES submissionType and submits successfully', async () => {
        const server = await constructTestPostgresServer()

        //Create and update a contract and rate submission to contract only with rate data
        const draft = await createAndUpdateTestHealthPlanPackage(server, {
            submissionType: 'CONTRACT_AND_RATES',
            documents: [
                {
                    name: 'contract_supporting_that_applies_to_a_rate_also.pdf',
                    s3URL: 'fakeS3URL',
                    documentCategories: [
                        'CONTRACT_RELATED' as const,
                        'RATES_RELATED' as const,
                    ],
                },
                {
                    name: 'rate_only_supporting_doc.pdf',
                    s3URL: 'fakeS3URL',
                    documentCategories: ['RATES_RELATED' as const],
                },
            ],
        })

        const draftCurrentRevision = draft.revisions[0].node
        const draftPackageData = base64ToDomain(
            draftCurrentRevision.formDataProto
        )

        if (draftPackageData instanceof Error) {
            throw new Error(draftPackageData.message)
        }

        const submitResult = await submitTestHealthPlanPackage(server, draft.id)
        const currentRevision = submitResult.revisions[0].node
        const packageData = base64ToDomain(currentRevision.formDataProto)

        if (packageData instanceof Error) {
            throw new Error(packageData.message)
        }

        expect(packageData).toEqual(
            expect.objectContaining({
                addtlActuaryContacts: draftPackageData.addtlActuaryContacts,
                documents: [
                    {
                        name: 'contract_supporting_that_applies_to_a_rate_also.pdf',
                        s3URL: 'fakeS3URL',
                        documentCategories: [
                            'CONTRACT_RELATED' as const,
                            'RATES_RELATED' as const,
                        ],
                    },
                    {
                        name: 'rate_only_supporting_doc.pdf',
                        s3URL: 'fakeS3URL',
                        documentCategories: ['RATES_RELATED' as const],
                    },
                ],
            })
        )
    })

    it('removes any rate data from CONTRACT_ONLY submissionType and submits successfully', async () => {
        const server = await constructTestPostgresServer()

        //Create and update a contract and rate submission to contract only with rate data
        const draft = await createAndUpdateTestHealthPlanPackage(server, {
            submissionType: 'CONTRACT_ONLY',
            documents: [
                {
                    name: 'contract_supporting_that_applies_to_a_rate_also.pdf',
                    s3URL: 'fakeS3URL',
                    documentCategories: [
                        'CONTRACT_RELATED' as const,
                        'RATES_RELATED' as const,
                    ],
                },
                {
                    name: 'rate_only_supporting_doc.pdf',
                    s3URL: 'fakeS3URL',
                    documentCategories: ['RATES_RELATED' as const],
                },
            ],
        })

        const submitResult = await submitTestHealthPlanPackage(server, draft.id)

        const currentRevision = submitResult.revisions[0].node
        const packageData = base64ToDomain(currentRevision.formDataProto)

        if (packageData instanceof Error) {
            throw new Error(packageData.message)
        }

        expect(packageData).toEqual(
            expect.objectContaining({
                rateInfos: expect.arrayContaining([]),
                addtlActuaryContacts: expect.arrayContaining([]),
                documents: [
                    {
                        name: 'contract_supporting_that_applies_to_a_rate_also.pdf',
                        s3URL: 'fakeS3URL',
                        documentCategories: ['CONTRACT_RELATED'],
                    },
                    {
                        name: 'rate_only_supporting_doc.pdf',
                        s3URL: 'fakeS3URL',
                        documentCategories: ['CONTRACT_RELATED'],
                    },
                ],
            })
        )
    })

    it('removes any invalid modified provisions from CHIP submission and submits successfully', async () => {
        const server = await constructTestPostgresServer()

        //Create and update a submission as if the user edited and changed population covered after filling out yes/nos
        const draft = await createAndUpdateTestHealthPlanPackage(server, {
            contractType: 'AMENDMENT',
            populationCovered: 'CHIP',
            federalAuthorities: ['TITLE_XXI'],
            contractAmendmentInfo: {
                modifiedProvisions: {
                    inLieuServicesAndSettings: true,
                    modifiedBenefitsProvided: true,
                    modifiedGeoAreaServed: false,
                    modifiedMedicaidBeneficiaries: false,
                    modifiedRiskSharingStrategy: true,
                    modifiedIncentiveArrangements: true,
                    modifiedWitholdAgreements: true,
                    modifiedStateDirectedPayments: true,
                    modifiedPassThroughPayments: true,
                    modifiedPaymentsForMentalDiseaseInstitutions: true,
                    modifiedMedicalLossRatioStandards: false,
                    modifiedOtherFinancialPaymentIncentive: false,
                    modifiedEnrollmentProcess: false,
                    modifiedGrevienceAndAppeal: false,
                    modifiedNetworkAdequacyStandards: false,
                    modifiedLengthOfContract: false,
                    modifiedNonRiskPaymentArrangements: false,
                },
            },
        })

        const submitResult = await submitTestHealthPlanPackage(server, draft.id)

        const currentRevision = submitResult.revisions[0].node
        const packageData = base64ToDomain(currentRevision.formDataProto)

        if (packageData instanceof Error) {
            throw new Error(packageData.message)
        }
        expect(packageData).toEqual(
            expect.objectContaining({
                contractAmendmentInfo: {
                    modifiedProvisions: {
                        modifiedBenefitsProvided: true,
                        modifiedGeoAreaServed: false,
                        modifiedMedicaidBeneficiaries: false,
                        modifiedMedicalLossRatioStandards: false,
                        modifiedEnrollmentProcess: false,
                        modifiedGrevienceAndAppeal: false,
                        modifiedNetworkAdequacyStandards: false,
                        modifiedLengthOfContract: false,
                        modifiedNonRiskPaymentArrangements: false,
                    },
                },
            })
        )
    })

    it('removes any invalid federal authorities from CHIP submission and submits successfully', async () => {
        const server = await constructTestPostgresServer()

        //Create and update a submission as if the user edited and changed population covered after filling out yes/nos
        const draft = await createAndUpdateTestHealthPlanPackage(server, {
            populationCovered: 'CHIP',
            federalAuthorities: [
                'STATE_PLAN',
                'WAIVER_1915B',
                'WAIVER_1115',
                'VOLUNTARY',
                'BENCHMARK',
                'TITLE_XXI',
            ],
        })

        const submitResult = await submitTestHealthPlanPackage(server, draft.id)

        const currentRevision = submitResult.revisions[0].node
        const packageData = base64ToDomain(currentRevision.formDataProto)

        if (packageData instanceof Error) {
            throw new Error(packageData.message)
        }
        expect(packageData).toEqual(
            expect.objectContaining({
                federalAuthorities: ['WAIVER_1115', 'TITLE_XXI'],
            })
        )
    })

    it('sends two emails', async () => {
        const mockEmailer = testEmailer()

        //mock invoke email submit lambda
        const server = await constructTestPostgresServer({
            emailer: mockEmailer,
        })
        const draft = await createAndUpdateTestHealthPlanPackage(server, {})
        const draftID = draft.id

        const submitResult = await server.executeOperation({
            query: SUBMIT_HEALTH_PLAN_PACKAGE,
            variables: {
                input: {
                    pkgID: draftID,
                },
            },
        })

        expect(submitResult.errors).toBeUndefined()
        expect(mockEmailer.sendEmail).toHaveBeenCalledTimes(2)
    })

    it('send CMS email to CMS if submission is valid', async () => {
        const config = testEmailConfig
        const mockEmailer = testEmailer(config)
        //mock invoke email submit lambda
        const server = await constructTestPostgresServer({
            emailer: mockEmailer,
        })
        const draft = await createAndUpdateTestHealthPlanPackage(server, {})
        const draftID = draft.id

        const submitResult = await server.executeOperation({
            query: SUBMIT_HEALTH_PLAN_PACKAGE,
            variables: {
                input: {
                    pkgID: draftID,
                },
            },
        })

        const currentRevision =
            submitResult?.data?.submitHealthPlanPackage?.pkg.revisions[0].node

        const sub = base64ToDomain(currentRevision.formDataProto)
        if (sub instanceof Error) {
            throw sub
        }

        const programs = [defaultFloridaProgram()]
        const name = packageName(sub, programs)
        const stateAnalystsEmails = getTestStateAnalystsEmails(sub.stateCode)

        const cmsEmails = [
            ...config.devReviewTeamEmails,
            ...stateAnalystsEmails,
        ]

        // email subject line is correct for CMS email
        expect(mockEmailer.sendEmail).toHaveBeenCalledWith(
            expect.objectContaining({
                subject: expect.stringContaining(
                    `New Managed Care Submission: ${name}`
                ),
                sourceEmail: config.emailSource,
                toAddresses: expect.arrayContaining(Array.from(cmsEmails)),
            })
        )
    })

    it('does send email when request for state analysts emails fails', async () => {
        const config = testEmailConfig
        const mockEmailer = testEmailer(config)
        //mock invoke email submit lambda
        const mockEmailParameterStore = mockEmailParameterStoreError()
        const server = await constructTestPostgresServer({
            emailer: mockEmailer,
            emailParameterStore: mockEmailParameterStore,
        })
        const draft = await createAndUpdateTestHealthPlanPackage(server, {})
        const draftID = draft.id

        await server.executeOperation({
            query: SUBMIT_HEALTH_PLAN_PACKAGE,
            variables: {
                input: {
                    pkgID: draftID,
                },
            },
        })

        expect(mockEmailer.sendEmail).toHaveBeenCalledWith(
            expect.objectContaining({
                toAddresses: expect.arrayContaining(
                    Array.from(config.devReviewTeamEmails)
                ),
            })
        )
    })

    it('does log error when request for state specific analysts emails failed', async () => {
        const mockEmailParameterStore = mockEmailParameterStoreError()
        const consoleErrorSpy = jest.spyOn(console, 'error')
        const error = {
            error: 'No store found',
            message: 'getStateAnalystsEmails failed',
            operation: 'getStateAnalystsEmails',
            status: 'ERROR',
        }

        const server = await constructTestPostgresServer({
            emailParameterStore: mockEmailParameterStore,
        })
        const draft = await createAndUpdateTestHealthPlanPackage(server, {})
        const draftID = draft.id

        await server.executeOperation({
            query: SUBMIT_HEALTH_PLAN_PACKAGE,
            variables: {
                input: {
                    pkgID: draftID,
                },
            },
        })

        expect(consoleErrorSpy).toHaveBeenCalledWith(error)
    })

    it('send state email to logged in user if submission is valid', async () => {
        const config = testEmailConfig
        const mockEmailer = testEmailer(config)
        const server = await constructTestPostgresServer({
            emailer: mockEmailer,
        })

        const currentUser = defaultContext().user // need this to reach into gql tests and understand who current user is
        const draft = await createAndUpdateTestHealthPlanPackage(server, {})
        const draftID = draft.id

        const submitResult = await server.executeOperation({
            query: SUBMIT_HEALTH_PLAN_PACKAGE,
            variables: {
                input: {
                    pkgID: draftID,
                },
            },
        })

        expect(submitResult.errors).toBeUndefined()

        const currentRevision =
            submitResult?.data?.submitHealthPlanPackage?.pkg.revisions[0].node

        const sub = base64ToDomain(currentRevision.formDataProto)
        if (sub instanceof Error) {
            throw sub
        }

        const programs = [defaultFloridaProgram()]
        const ratePrograms = [defaultFloridaRateProgram()]
        const name = packageName(sub, programs)
        const rateName = generateRateName(sub, sub.rateInfos[0], ratePrograms)

        expect(mockEmailer.sendEmail).toHaveBeenCalledWith(
            expect.objectContaining({
                subject: expect.stringContaining(`${name} was sent to CMS`),
                sourceEmail: config.emailSource,
                toAddresses: expect.arrayContaining([currentUser.email]),
                bodyHTML: expect.stringContaining(rateName),
            })
        )
    })

    it('send state email to submitter if submission is valid', async () => {
        const mockEmailer = testEmailer()
        const server = await constructTestPostgresServer({
            emailer: mockEmailer,
            context: {
                user: testStateUser({
                    email: 'notspiderman@example.com',
                }),
            },
        })
        const draft = await createAndUpdateTestHealthPlanPackage(server, {})
        const draftID = draft.id

        const submitResult = await server.executeOperation({
            query: SUBMIT_HEALTH_PLAN_PACKAGE,
            variables: {
                input: {
                    pkgID: draftID,
                },
            },
        })

        expect(submitResult.errors).toBeUndefined()

        const currentRevision =
            submitResult?.data?.submitHealthPlanPackage?.pkg.revisions[0].node

        const sub = base64ToDomain(currentRevision.formDataProto)
        if (sub instanceof Error) {
            throw sub
        }

        const programs = [defaultFloridaProgram()]
        const name = packageName(sub, programs)

        expect(mockEmailer.sendEmail).toHaveBeenCalledWith(
            expect.objectContaining({
                subject: expect.stringContaining(`${name} was sent to CMS`),
                toAddresses: expect.arrayContaining([
                    'notspiderman@example.com',
                ]),
            })
        )
    })

    it('send CMS email to CMS on valid resubmission', async () => {
        const config = testEmailConfig
        const mockEmailer = testEmailer(config)
        //mock invoke email submit lambda
        const stateServer = await constructTestPostgresServer({
            emailer: mockEmailer,
        })

        const stateSubmission = await createAndSubmitTestHealthPlanPackage(
            stateServer
        )
        const cmsServer = await constructTestPostgresServer({
            context: {
                user: cmsUser,
            },
        })

        await unlockTestHealthPlanPackage(
            cmsServer,
            stateSubmission.id,
            'Test unlock reason.'
        )

        const submitResult = await stateServer.executeOperation({
            query: SUBMIT_HEALTH_PLAN_PACKAGE,
            variables: {
                input: {
                    pkgID: stateSubmission.id,
                    submittedReason: 'Test resubmitted reason',
                },
            },
        })

        const currentRevision =
            submitResult?.data?.submitHealthPlanPackage?.pkg.revisions[0].node

        const sub = base64ToDomain(currentRevision.formDataProto)
        if (sub instanceof Error) {
            throw sub
        }

        const programs = [defaultFloridaProgram()]
        const name = packageName(sub, programs)

        // email subject line is correct for CMS email and contains correct email body text
        expect(mockEmailer.sendEmail).toHaveBeenCalledWith(
            expect.objectContaining({
                subject: expect.stringContaining(`${name} was resubmitted`),
                sourceEmail: config.emailSource,
                bodyText: expect.stringContaining(
                    `The state completed their edits on submission ${name}`
                ),
                toAddresses: expect.arrayContaining(
                    Array.from(config.devReviewTeamEmails)
                ),
            })
        )
    })

    it('send state email to state contacts and all submitters on valid resubmission', async () => {
        const config = testEmailConfig
        const mockEmailer = testEmailer(config)
        //mock invoke email submit lambda
        const stateServer = await constructTestPostgresServer({
            context: {
                user: testStateUser({
                    email: 'alsonotspiderman@example.com',
                }),
            },
        })

        const stateServerTwo = await constructTestPostgresServer({
            emailer: mockEmailer,
            context: {
                user: testStateUser({
                    email: 'notspiderman@example.com',
                }),
            },
        })

        const stateSubmission = await createAndSubmitTestHealthPlanPackage(
            stateServer
        )

        const cmsServer = await constructTestPostgresServer({
            context: {
                user: cmsUser,
            },
        })

        await unlockTestHealthPlanPackage(
            cmsServer,
            stateSubmission.id,
            'Test unlock reason.'
        )

        const submitResult = await resubmitTestHealthPlanPackage(
            stateServerTwo,
            stateSubmission.id,
            'Test resubmission reason'
        )

        const currentRevision = submitResult?.revisions[0].node

        const sub = base64ToDomain(currentRevision.formDataProto)
        if (sub instanceof Error) {
            throw sub
        }

        const programs = [defaultFloridaProgram()]
        const name = packageName(sub, programs)

        // email subject line is correct for CMS email and contains correct email body text
        expect(mockEmailer.sendEmail).toHaveBeenCalledWith(
            expect.objectContaining({
                subject: expect.stringContaining(`${name} was resubmitted`),
                sourceEmail: config.emailSource,
                toAddresses: expect.arrayContaining([
                    'alsonotspiderman@example.com',
                    'notspiderman@example.com',
                    sub.stateContacts[0].email,
                ]),
            })
        )
    })

    it('does not send any emails if submission fails', async () => {
        const mockEmailer = testEmailer()
        const server = await constructTestPostgresServer({
            emailer: mockEmailer,
        })
        const draft = await createAndUpdateTestHealthPlanPackage(server, {
            submissionType: 'CONTRACT_AND_RATES',
            rateInfos: [
                {
                    rateDateStart: new Date(Date.UTC(2025, 5, 1)),
                    rateDateEnd: new Date(Date.UTC(2026, 4, 30)),
                    rateDateCertified: undefined,
                    rateDocuments: [],
                    supportingDocuments: [],
                    actuaryContacts: [],
                    packagesWithSharedRateCerts: [],
                },
            ],
        })
        const draftID = draft.id

        const submitResult = await server.executeOperation({
            query: SUBMIT_HEALTH_PLAN_PACKAGE,
            variables: {
                input: {
                    pkgID: draftID,
                },
            },
        })

        expect(submitResult.errors).toBeDefined()
        expect(mockEmailer.sendEmail).not.toHaveBeenCalled()
    })

    it('errors when SES email has failed.', async () => {
        const mockEmailer = testEmailer()

        jest.spyOn(awsSESHelpers, 'testSendSESEmail').mockImplementation(
            async () => {
                throw new Error('Network error occurred')
            }
        )

        //mock invoke email submit lambda
        const server = await constructTestPostgresServer({
            emailer: mockEmailer,
        })
        const draft = await createAndUpdateTestHealthPlanPackage(server, {})
        const draftID = draft.id

        const submitResult = await server.executeOperation({
            query: SUBMIT_HEALTH_PLAN_PACKAGE,
            variables: {
                input: {
                    pkgID: draftID,
                },
            },
        })

        // expect errors from submission
        expect(submitResult.errors).toBeDefined()

        // expect sendEmail to have been called, so we know it did not error earlier
        expect(mockEmailer.sendEmail).toHaveBeenCalled()

        // expect correct graphql error.
        expect(submitResult.errors?.[0]).toEqual(
            expect.objectContaining({
                message: 'Email failed',
                locations: [{ line: 2, column: 5 }],
                path: ['submitHealthPlanPackage'],
                extensions: {
                    code: 'INTERNAL_SERVER_ERROR',
                    cause: 'EMAIL_ERROR',
                    exception: {
                        message: 'Email failed',
                        path: undefined,
                        locations: undefined,
                    },
                },
            })
        )
    })

    it('errors when risk based question is undefined', async () => {
        const server = await constructTestPostgresServer()

        // setup
        const initialPkg = await createAndUpdateTestHealthPlanPackage(server, {
            riskBasedContract: undefined,
        })
        const draft = latestFormData(initialPkg)
        const draftID = draft.id

        await new Promise((resolve) => setTimeout(resolve, 2000))

        // submit
        const submitResult = await server.executeOperation({
            query: SUBMIT_HEALTH_PLAN_PACKAGE,
            variables: {
                input: {
                    pkgID: draftID,
                },
            },
        })

        expect(submitResult.errors).toBeDefined()
        expect(submitResult.errors?.[0].extensions?.message).toBe(
            'formData is missing required contract fields'
        )
    }, 20000)
})

describe('Feature flagged population coverage question test', () => {
    it('errors when population coverage question is undefined', async () => {
        const mockLDService = testLDService({ 'chip-only-form': true })
        const server = await constructTestPostgresServer({
            ldService: mockLDService,
        })

        // setup
        const initialPkg = await createAndUpdateTestHealthPlanPackage(server, {
            populationCovered: undefined,
        })
        const draft = latestFormData(initialPkg)
        const draftID = draft.id

        await new Promise((resolve) => setTimeout(resolve, 2000))

        // submit
        const submitResult = await server.executeOperation({
            query: SUBMIT_HEALTH_PLAN_PACKAGE,
            variables: {
                input: {
                    pkgID: draftID,
                },
            },
        })

        expect(submitResult.errors).toBeDefined()
        expect(submitResult.errors?.[0].extensions?.message).toBe(
            'formData is missing required contract fields'
        )
    }, 20000)
})
