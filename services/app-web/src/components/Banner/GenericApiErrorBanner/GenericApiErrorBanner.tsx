import React from 'react'
import styles from '../Banner.module.scss'
import { Alert, Link } from '@trussworks/react-uswds'
import { ERROR_MESSAGES } from '../../../constants/errors'
import { useStringConstants } from '../../../hooks/useStringConstants'

export type GenericApiErrorProps = {
    heading?: string
    message?: string
    suggestion?: string
}

export const GenericApiErrorBanner = ({
    heading,
    message,
    suggestion,
}: GenericApiErrorProps): React.ReactElement => {
    const stringConstants = useStringConstants()
    const MAIL_TO_SUPPORT = stringConstants.MAIL_TO_SUPPORT
    return (
        <Alert
            role="alert"
            type="error"
            heading={heading || 'System error'}
            headingLevel="h4"
            validation
            data-testid="error-alert"
        >
            <div className={styles.bannerBodyText}>
                <p className="usa-alert__text">
                    <b>{message || ERROR_MESSAGES.generic_error}</b>
                </p>
                <p className="usa-alert__text">
                    {suggestion ? (
                        <span>{suggestion} </span>
                    ) : (
                        <>
                            <span>
                                Please refresh your browser and if you continue
                                to experience an error,&nbsp;
                            </span>
                            <Link href={MAIL_TO_SUPPORT}>let us know.</Link>
                        </>
                    )}
                </p>
            </div>
        </Alert>
    )
}
