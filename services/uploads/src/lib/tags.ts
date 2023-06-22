import { Tag } from '@aws-sdk/client-s3'

// Constants for tagging file after a virus scan.
const VIRUS_SCAN_STATUS_KEY = 'virusScanStatus'
const VIRUS_SCAN_TIMESTAMP_KEY = 'virusScanTimestamp'
const ScanStatusValues = ['CLEAN', 'INFECTED', 'ERROR', 'SKIPPED'] as const
type ScanStatus = (typeof ScanStatusValues)[number]

function isScanStatus(value: unknown): value is ScanStatus {
    if (typeof value === 'string') {
        return (ScanStatusValues as ReadonlyArray<string>).includes(value)
    }
    return false
}

/**
 * Generates the set of tags that will be used to tag the files of S3.
 */
function generateVirusScanTagSet(virusScanStatus: ScanStatus) {
    return {
        TagSet: [
            {
                Key: VIRUS_SCAN_STATUS_KEY,
                Value: virusScanStatus,
            },
            {
                Key: VIRUS_SCAN_TIMESTAMP_KEY,
                Value: new Date().getTime().toString(),
            },
        ],
    }
}

/**
 * Returns the virus scan status from a set of S3 tags.
 */
function virusScanStatus(tags: Tag[]): ScanStatus | Error | undefined {
    for (const tag of tags) {
        if (tag.Key === VIRUS_SCAN_STATUS_KEY) {
            if (!tag.Value) {
                return new Error('No Value in this tag.')
            }

            if (isScanStatus(tag.Value)) {
                return tag.Value
            }
            return new Error(
                'Tag has an invalid Value, not one of our Statuses'
            )
        }
    }

    return undefined
}

function generateUploadedAtTagSet() {
    return {
        TagSet: [
            {
                Key: 'uploadedAt',
                Value: new Date().toISOString(),
            },
        ],
    }
}

function parseUploadedAtFromTags(tags: Tag[]): Date | Error | undefined {
    for (const tag of tags) {
        if (tag.Key === 'uploadedAt') {
            if (!tag.Value) {
                return new Error('No Value in this tag.')
            }

            return new Date(tag.Value)
        }
    }

    return undefined
}

export {
    generateVirusScanTagSet,
    virusScanStatus,
    parseUploadedAtFromTags as uploadedAt,
    generateUploadedAtTagSet,
    isScanStatus,
    VIRUS_SCAN_STATUS_KEY,
    VIRUS_SCAN_TIMESTAMP_KEY,
}

export type { ScanStatus }
