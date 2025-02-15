import { MockedResponse } from '@apollo/client/testing'
import {
    CmsUser,
    FetchCurrentUserDocument,
    User as UserType,
    AdminUser,
    IndexUsersDocument,
    IndexUsersQuery,
    StateUser,
} from '../../gen/gqlClient'

import { mockMNState } from './stateMock'
function mockValidUser(userData?: Partial<StateUser>): StateUser {
    return {
        __typename: 'StateUser' as const,
        id: 'foo-id',
        state: mockMNState(),
        role: 'STATE_USER',
        givenName: 'bob',
        familyName: 'ddmas',
        email: 'bob@dmas.mn.gov',
        ...userData,
    }
}

function mockValidCMSUser(userData?: Partial<CmsUser>): CmsUser {
    return {
        __typename: 'CMSUser' as const,
        id: 'bar-id',
        role: 'CMS_USER',
        givenName: 'bob',
        familyName: 'ddmas',
        email: 'bob@dmas.mn.gov',
        divisionAssignment: 'DMCO',
        stateAssignments: [],
        ...userData,
    }
}

function mockValidAdminUser(userData?: Partial<AdminUser>): AdminUser {
    return {
        __typename: 'AdminUser' as const,
        id: 'bar-id',
        role: 'ADMIN_USER',
        givenName: 'bob',
        familyName: 'ddmas',
        email: 'bob@dmas.mn.gov',
        ...userData,
    }
}

type fetchCurrentUserMockProps = {
    user?: UserType | Partial<UserType>
    statusCode: 200 | 403 | 500
}
const fetchCurrentUserMock = ({
    user = mockValidUser(),
    statusCode,
}: // eslint-disable-next-line @typescript-eslint/no-explicit-any
fetchCurrentUserMockProps): MockedResponse<Record<string, any>> => {
    switch (statusCode) {
        case 200:
            return {
                request: { query: FetchCurrentUserDocument },
                result: {
                    data: {
                        fetchCurrentUser: user,
                    },
                },
            }
        case 403:
            return {
                request: { query: FetchCurrentUserDocument },
                error: new Error('You are not logged in'),
            }
        default:
            return {
                request: { query: FetchCurrentUserDocument },
                error: new Error('A network error occurred'),
            }
    }
}

const indexUsersQueryMock = (): MockedResponse<IndexUsersQuery> => {
    return {
        request: {
            query: IndexUsersDocument,
        },
        result: {
            data: {
                indexUsers: {
                    totalCount: 1,
                    edges: [
                        {
                            node: {
                                __typename: 'CMSUser',
                                role: 'CMS_USER',
                                id: '1',
                                familyName: 'Hotman',
                                givenName: 'Zuko',
                                divisionAssignment: null,
                                email: 'zuko@example.com',
                                stateAssignments: [],
                            },
                        },
                    ],
                },
            },
        },
    }
}

export {
    fetchCurrentUserMock,
    mockValidCMSUser,
    mockValidUser,
    mockValidAdminUser,
    indexUsersQueryMock,
}
