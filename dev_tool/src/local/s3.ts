import LabeledProcessRunner from '../runner.js'

// runS3Locally runs s3 locally
export async function runS3Locally(runner: LabeledProcessRunner) {
    // eslint-disable-next-line @typescript-eslint/no-floating-promises
    runner.runCommandAndOutput(
        's3',
        ['lerna', 'run', 'start', '--scope=uploads'],
        ''
    )
}
