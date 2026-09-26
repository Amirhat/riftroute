import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { Badge, Card, OwnerBadge, Stat } from './ui'

describe('ui components render', () => {
  it('Badge shows its children', () => {
    render(<Badge tone="vpn">active</Badge>)
    expect(screen.getByText('active')).toBeInTheDocument()
  })

  it('OwnerBadge labels the owner', () => {
    render(<OwnerBadge owner="riftroute" />)
    expect(screen.getByText(/riftroute/i)).toBeInTheDocument()
  })

  it('Card tones replace the neutral border and fill instead of stacking on them', () => {
    render(
      <>
        <Card>plain</Card>
        <Card tone="danger">failed</Card>
        <Card tone="warning" className="p-3">careful</Card>
      </>,
    )
    expect(screen.getByText('plain')).toHaveClass('border-line', 'bg-surface')
    expect(screen.getByText('failed')).toHaveClass('border-danger/40', 'bg-danger/5')
    expect(screen.getByText('failed')).not.toHaveClass('border-line', 'bg-surface')
    expect(screen.getByText('careful')).toHaveClass('border-warning/40', 'bg-warning/5', 'p-3')
    expect(screen.getByText('careful')).not.toHaveClass('border-line', 'bg-surface')
  })

  it('Stat shows a label and value', () => {
    render(<Stat label="Uptime" value="1h 2m" />)
    expect(screen.getByText('Uptime')).toBeInTheDocument()
    expect(screen.getByText('1h 2m')).toBeInTheDocument()
  })
})
