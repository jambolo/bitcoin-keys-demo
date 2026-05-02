import { Dispatch, SetStateAction, useCallback, useEffect, useMemo, useState } from 'react'

type Serializer<T> = {
  parse: (raw: string) => T
  stringify: (value: T) => string
}

const defaultSerializer: Serializer<unknown> = {
  parse: (raw: string) => JSON.parse(raw),
  stringify: (value: unknown) => JSON.stringify(value),
}

export function usePersistentKV<T = string>(
  key: string,
  initialValue: T,
  serializer?: Serializer<T>
): [T, Dispatch<SetStateAction<T>>] {
  const activeSerializer = useMemo(
    () => serializer ?? (defaultSerializer as Serializer<T>),
    [serializer]
  )

  const readValue = useCallback((): T => {
    if (typeof window === 'undefined') {
      return initialValue
    }

    try {
      const stored = window.localStorage.getItem(key)
      if (stored === null) {
        return initialValue
      }

      return activeSerializer.parse(stored)
    } catch {
      return initialValue
    }
  }, [activeSerializer, initialValue, key])

  const [value, setValue] = useState<T>(readValue)

  useEffect(() => {
    setValue(readValue())
  }, [readValue])

  const setPersistentValue: Dispatch<SetStateAction<T>> = useCallback(
    (next) => {
      setValue((previous) => {
        const resolved = next instanceof Function ? next(previous) : next

        try {
          window.localStorage.setItem(key, activeSerializer.stringify(resolved))
        } catch {
          // Ignore storage write failures (private mode/quota issues)
        }

        return resolved
      })
    },
    [activeSerializer, key]
  )

  useEffect(() => {
    const onStorage = (event: StorageEvent) => {
      if (event.storageArea !== window.localStorage || event.key !== key) {
        return
      }

      if (event.newValue === null) {
        setValue(initialValue)
        return
      }

      try {
        setValue(activeSerializer.parse(event.newValue))
      } catch {
        setValue(initialValue)
      }
    }

    window.addEventListener('storage', onStorage)
    return () => window.removeEventListener('storage', onStorage)
  }, [activeSerializer, initialValue, key])

  return [value, setPersistentValue]
}
