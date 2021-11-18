import { PrismaClient } from '@prisma/client'
import { Store } from '../store/store'
import { findProgram } from '../store/findProgram'

import { findAllSubmissions } from './findAllSubmissions'
import { insertDraftSubmission } from './insertDraftSubmission'
import { updateDraftSubmission } from './updateDraftSubmission'
import { updateStateSubmission } from './updateStateSubmission'
import { findDraftSubmission } from './findDraftSubmission'
import { findStateSubmission } from './findStateSubmission'

function NewPostgresStore(client: PrismaClient): Store {
    return {
        findAllSubmissions: (stateCode) =>
            findAllSubmissions(client, stateCode),
        insertDraftSubmission: (args) => insertDraftSubmission(client, args),
        findDraftSubmission: (draftUUID) =>
            findDraftSubmission(client, draftUUID),
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        findDraftSubmissionByStateNumber: (_stateCode, _stateNumber) => {
            throw new Error('UNIMPLEMENTED')
        },
        updateDraftSubmission: (draftSubmission) =>
            updateDraftSubmission(client, draftSubmission),
        updateStateSubmission: (submission) =>
            updateStateSubmission(client, submission),
        findStateSubmission: (submissionID) =>
            findStateSubmission(client, submissionID),
        findProgram: findProgram,
    }
}

export { NewPostgresStore }
