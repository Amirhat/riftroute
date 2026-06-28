import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { Badge, OwnerBadge, Stat } from './ui'

describe('ui components render', () => {
  it('Badge shows its children', () => {
    render(<Badge tone="vpn">active</Badge>)
    expect(screen.getByText('active')).toBeInTheDocument()
  })

  it('OwnerBadge labels the owner', () => {
    render(<OwnerBadge owner="riftroute" />)
    expect(screen.getByText(/riftroute/i)).toBeInTheDocument()
  })

  it('Stat shows a label and value', () => {
    render(<Stat label="Uptime" value="1h 2m" />)
    expect(screen.getByText('Uptime')).toBeInTheDocument()
    expect(screen.getByText('1h 2m')).toBeInTheDocument()
  })
})
