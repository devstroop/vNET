import { useCallback, useEffect, useRef, useState } from 'react'
import { ApiError } from '@/api/client'

type ResourceState<T> = {
  data: T | null
  error: string | null
  loading: boolean
  updatedAt: number | null
}

export function useResource<T>(fetcher: () => Promise<T>, intervalMs = 0) {
  const [state, setState] = useState<ResourceState<T>>({
    data: null,
    error: null,
    loading: true,
    updatedAt: null,
  })
  const fetcherRef = useRef(fetcher)
  const requestId = useRef(0)

  useEffect(() => {
    fetcherRef.current = fetcher
  }, [fetcher])

  const load = useCallback(async () => {
    const id = ++requestId.current
    setState((current) => ({ ...current, loading: true }))
    try {
      const data = await fetcherRef.current()
      if (requestId.current !== id) return
      setState({ data, error: null, loading: false, updatedAt: Date.now() })
    } catch (error) {
      if (requestId.current !== id) return
      const message =
        error instanceof ApiError
          ? error.message
          : error instanceof Error
            ? error.message
            : 'Unable to reach the control service.'
      setState((current) => ({
        ...current,
        error: message,
        loading: false,
      }))
    }
  }, [])

  useEffect(() => {
    void load()
    if (!intervalMs) return
    const timer = window.setInterval(() => {
      void load()
    }, intervalMs)
    return () => window.clearInterval(timer)
  }, [load, intervalMs])

  return { ...state, refresh: load }
}
