import React from 'react'
import { Link, ButtonGroup, Button } from '@trussworks/react-uswds'

import styles from './ReviewSubmit/ReviewSubmit.module.scss'

/* 
TODO
    - Refactor to handle dynamic components (NavLinks and Buttons) that will have different onClick and to/href depending on page
    - make new prop exit Action for what is right now "Save as draft". This will conditionally display
*/
export type PageActionsProps = {
    secondaryAction: string
    primaryAction: string
}

export const PageActions = ({
    secondaryAction,
    primaryAction,
}: PageActionsProps): React.ReactElement => {
    return (
        <div className={styles.pageActions}>
            <Link href="#">Save as draft</Link>
            <ButtonGroup type="default" className={styles.buttonGroup}>
                <Link
                    variant="unstyled"
                    href="#"
                    className="usa-button usa-button--outline"
                >
                    {secondaryAction}
                </Link>
                <Button type="button" className={styles.submitButton}>
                    {primaryAction}
                </Button>
            </ButtonGroup>
        </div>
    )
}
