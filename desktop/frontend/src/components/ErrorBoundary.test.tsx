import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { ErrorBoundary } from './ErrorBoundary'

function Boom(): JSX.Element {
  throw new Error('kaboom')
}

describe('ErrorBoundary', () => {
  beforeEach(() => vi.spyOn(console, 'error').mockImplementation(() => {}))
  afterEach(() => vi.restoreAllMocks())

  it('renders children normally', () => {
    render(<ErrorBoundary><div>hello</div></ErrorBoundary>)
    expect(screen.getByText('hello')).toBeInTheDocument()
  })

  it('catches a render error and shows a message instead of blanking', () => {
    render(<ErrorBoundary><Boom /></ErrorBoundary>)
    expect(screen.getByText(/Couldn’t render this view/)).toBeInTheDocument()
    expect(screen.getByText('kaboom')).toBeInTheDocument()
    expect(screen.getByText('Try again')).toBeInTheDocument()
  })
})
