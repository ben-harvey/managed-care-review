import { render } from '@testing-library/react'
import { Tabs } from './Tabs'
import { TabPanel } from './TabPanel'

describe('Tabs', () => {
    it('renders without errors', async () => {
        const { getByTestId } = render(
            <Tabs>
                <TabPanel id="Test-Pepperoni" tabName="Pepperoni">
                    <h1>Pepperoni</h1>
                </TabPanel>
                <TabPanel id="Test-Sausage" tabName="Sausage">
                    <h1>Sausage</h1>
                </TabPanel>
                <TabPanel id="Test-Mushroom" tabName="Mushroom">
                    <h1>Mushroom</h1>
                </TabPanel>
                <TabPanel id="Test-Bacon" tabName="Bacon">
                    <h1>Bacon</h1>
                </TabPanel>
            </Tabs>
        )
        expect(getByTestId('tabs')).toBeInTheDocument()
    })
})
