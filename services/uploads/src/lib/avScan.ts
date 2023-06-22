import { S3UploadsClient } from '../deps/s3'
import { ClamAV } from '../deps/clamAV'
import {
    generateVirusScanTagSet,
    ScanStatus,
    VIRUS_SCAN_TIMESTAMP_KEY,
    VIRUS_SCAN_STATUS_KEY,
} from './tags'
import { scanFiles } from './scanFiles'

export async function scanFile(
    s3Client: S3UploadsClient,
    clamAV: ClamAV,
    key: string,
    bucket: string,
    maxFileSize: number,
    scanDir: string
): Promise<undefined | Error> {
    //You need to verify that you are not getting too large a file
    //currently lambdas max out at 500MB storage.
    const fileSize = await s3Client.sizeOf(key, bucket)
    if (fileSize instanceof Error) {
        return fileSize
    }

    // Get current tags
    const currentTagsResult = await s3Client.getObjectTags(key, bucket)
    if (currentTagsResult instanceof Error) {
        return currentTagsResult
    }

    let hasVirusScanStatusTag = false
    let hasVirusScanTimeStampTag = false

    // Check if virus scan tags already exist
    for (const tag of currentTagsResult) {
        if (tag.Key === VIRUS_SCAN_STATUS_KEY) {
            hasVirusScanStatusTag = true
        }
        if (tag.Key === VIRUS_SCAN_TIMESTAMP_KEY) {
            hasVirusScanTimeStampTag = true
        }
    }

    // If both exist skip scanning and adding the tags
    if (hasVirusScanStatusTag && hasVirusScanTimeStampTag) {
        console.info('File already scanned, skipping additional scanning.')
        return
    }

    // Remove virus scan tags, at this point only one would exist and to keep both tags in sync we want to remove the single tag.
    // Duplicate tags would cause avScan errors.
    const filteredCurrentTags = currentTagsResult.filter(
        (tags) =>
            tags.Key !== VIRUS_SCAN_TIMESTAMP_KEY &&
            tags.Key !== VIRUS_SCAN_STATUS_KEY
    )

    let tagResult: ScanStatus | undefined = undefined
    if (fileSize > maxFileSize) {
        console.warn('S3 File is too big. Size: ', fileSize)
        // tag with skipped.
        tagResult = 'SKIPPED'
    } else {
        const infectedFiles = await scanFiles(
            s3Client,
            clamAV,
            [key],
            bucket,
            scanDir
        )

        if (infectedFiles instanceof Error) {
            tagResult = 'ERROR'
        } else {
            if (infectedFiles.length === 0) {
                tagResult = 'CLEAN'
            } else {
                tagResult = 'INFECTED'
            }
        }
    }

    const tags = generateVirusScanTagSet(tagResult)
    // tagObject replaces existing tags, so we get the tags, add the new ones, and then set them all back
    const updatedTags = { TagSet: filteredCurrentTags.concat(tags.TagSet) }

    const err = await s3Client.tagObject(key, bucket, updatedTags)
    console.info('Updated tags ', updatedTags)

    if (err instanceof Error) {
        return err
    }

    console.info('Tagged object ', tagResult)
}
