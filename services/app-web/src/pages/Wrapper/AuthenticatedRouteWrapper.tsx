import React, { useState } from 'react'
import { Modal } from '../../components/Modal/Modal'
import { ModalRef } from '@trussworks/react-uswds'
import { createRef, useCallback, useEffect } from 'react'
import { useAuth } from '../../contexts/AuthContext'
import { AuthModeType } from '../../common-code/config'
import { extendSession } from '../Auth/cognitoAuth'
import { featureFlags } from '../../common-code/featureFlags/flags'
import styles from '../StateSubmission/ReviewSubmit/ReviewSubmit.module.scss'
import { dayjs } from '../../common-code/dateHelpers/dayjs'
import { useLDClient } from 'launchdarkly-react-client-sdk'
import { recordJSException } from '../../otelHelpers'
import { ErrorAlertSignIn } from '../../components'

export const AuthenticatedRouteWrapper = ({
    children,
    setAlert,
    authMode,
}: {
    children: React.ReactNode
    setAlert?: React.Dispatch<React.ReactElement>
    authMode: AuthModeType
}): React.ReactElement => {
    const {
        logout,
        sessionIsExpiring,
        logoutCountdownDuration,
        updateSessionExpirationState,
        updateSessionExpirationTime,
        setLogoutCountdownDuration,
    } = useAuth()
    const [announcementSeed] = useState<number>(logoutCountdownDuration)
    const announcementTimes: number[] = []
    for (let i = announcementSeed; i > 0; i -= 10) {
        announcementTimes.push(i)
    }
    const modalRef = createRef<ModalRef>()
    const ldClient = useLDClient()
    const countdownDuration: number =
        ldClient?.variation(
            featureFlags.MODAL_COUNTDOWN_DURATION.flag,
            featureFlags.MODAL_COUNTDOWN_DURATION.defaultValue
        ) * 60

    const logoutSession = useCallback(
        (forcedSessionSignout: boolean) => {
            updateSessionExpirationState(false)
            if (logout) {
                logout({ sessionTimeout: forcedSessionSignout }).catch((e) => {
                    recordJSException(`Error with logout: ${e}`)
                    setAlert && setAlert(<ErrorAlertSignIn />)
                })
            }
        },
        [logout, setAlert, updateSessionExpirationState]
    )

    const resetSessionTimeout = () => {
        updateSessionExpirationState(false)
        updateSessionExpirationTime()
        setLogoutCountdownDuration(countdownDuration)
        if (authMode !== 'LOCAL') {
            void extendSession()
        }
    }

    useEffect(() => {
        modalRef.current?.toggleModal(undefined, sessionIsExpiring)
    }, [sessionIsExpiring, modalRef])

    useEffect(() => {
        if (logoutCountdownDuration < 1) {
            logoutSession(true)
        }
    }, [logoutCountdownDuration, logoutSession])
    return (
        <>
            {
                <Modal
                    modalRef={modalRef}
                    id="extend-session-modal"
                    modalHeading="Session Expiring"
                    onSubmitText="Continue Session"
                    onCancelText="Logout"
                    onCancel={() => logoutSession(false)}
                    submitButtonProps={{ className: styles.submitButton }}
                    onSubmit={resetSessionTimeout}
                    forceAction={true}
                >
                    <p
                        aria-live={
                            announcementTimes.includes(logoutCountdownDuration)
                                ? 'assertive'
                                : 'off'
                        }
                        aria-atomic={true}
                    >
                        Your session is going to expire in{' '}
                        {dayjs
                            .duration(logoutCountdownDuration, 'seconds')
                            .format('mm:ss')}{' '}
                    </p>
                    <p>
                        If you would like to extend your session, click the
                        Continue Session button
                    </p>
                    <p>
                        If you would like to end your session now, click the
                        Logout button
                    </p>
                </Modal>
            }
            {children}
        </>
    )
}
