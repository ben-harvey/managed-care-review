type StateType = {
    code: string
    name: string
    programs: ProgramArgType[]
}

interface ProgramArgType {
    id: string
    name: string // short name. This is used most often in the application including in submission name
    fullName: string // full name is used in submission summary page
}

export type { StateType, ProgramArgType }
