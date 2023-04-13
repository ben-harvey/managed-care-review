/* eslint-disable @typescript-eslint/no-floating-promises */
import LabeledProcessRunner from '../runner.js'
import { compileGraphQLTypesWatchOnce } from './graphql.js'
import { installPrismaDeps } from './postgres.js'

export async function installAPIDeps(runner: LabeledProcessRunner) {
    // prisma requires that prisma generate is run after any yarn install
    return installPrismaDeps(runner)
}

// runAPILocally uses the serverless-offline plugin to run the api lambdas locally
export async function runAPILocally(runner: LabeledProcessRunner) {
    compileGraphQLTypesWatchOnce(runner)

    await installAPIDeps(runner)

    runner.runCommandAndOutput(
        'api',
        ['lerna', 'run', 'start', '--scope=app-api'],
        ''
    )
}
