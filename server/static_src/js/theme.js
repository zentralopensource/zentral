(() => {
    'use strict'

    // Setters and Getters for Themes
    const getStoredTheme = () => localStorage.getItem('theme')
    const setStoredTheme = theme => localStorage.setItem('theme', theme)
    const getPreferredTheme = () => {
        const storedTheme = getStoredTheme()
        if (storedTheme) {
          return storedTheme
        }

        return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
      }
    const setTheme = theme => {
        if (theme === 'auto' && window.matchMedia('(prefers-color-scheme: dark)').matches) {
            document.querySelectorAll("[data-bs-theme]").forEach(element => {
                document.documentElement.setAttribute('data-bs-theme', 'dark')
            })
            setDark()
        } else {
            document.querySelectorAll("[data-bs-theme]").forEach(element => {
                element.setAttribute('data-bs-theme', theme)
            })
            if (theme === 'dark') {
                setDark()
            }
            if (theme === 'light') {
                setLight()
            }
        }
    }
    const setDark = () => {
        document.querySelectorAll([".light", "[class*='-light']"]).forEach(element => {
            element.className = element.className.replace("light","dark")
        })
        document.querySelectorAll([".text-dark"]).forEach(element => {
            element.classList.remove('text-dark')
            element.classList.add('text-light')
        })
        document.getElementById("zentral-logo").src='/static_debug/logo-dark.svg'  // FIXME Hardcoded
    }
    const setLight = () => {
        document.querySelectorAll([".dark", "[class*='-dark']"]).forEach(element => {
            element.className = element.className.replace("dark","light")
        })
        document.querySelectorAll([".text-light"]).forEach(element => {
            element.classList.remove('text-light')
            element.classList.add('text-dark')
        })
        document.getElementById("zentral-logo").src='/static_debug/logo-light.svg'  // FIXME Hardcoded
    }

    const showActiveTheme = (theme, focus = false) => {
        const themeSwitcher = document.querySelector('#bd-theme')

        if (!themeSwitcher) {
          return
        }

        const btnToActive = document.querySelector(`[data-bs-theme-value="${theme}"]`)

        document.querySelectorAll('[data-bs-theme-value]').forEach(element => {
          element.classList.remove('active')
          element.setAttribute('aria-pressed', 'false')
        })

        btnToActive.classList.add('active')
        btnToActive.setAttribute('aria-pressed', 'true')

        if (focus) {
          themeSwitcher.focus()
        }
    }

    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
        const storedTheme = getStoredTheme()
        if (storedTheme !== 'light' && storedTheme !== 'dark') {
          setTheme(getPreferredTheme())
        }
      })

    window.addEventListener('DOMContentLoaded', () => {
        // Setting preferred theme
        showActiveTheme(getPreferredTheme())
        setTheme(getPreferredTheme())

        // Event handlers for changing themes.
        document.querySelectorAll('[data-bs-theme-value]')
          .forEach(toggle => {
            toggle.addEventListener('click', () => {
              const theme = toggle.getAttribute('data-bs-theme-value')
              setStoredTheme(theme)
              setTheme(theme)
              showActiveTheme(theme, true)
            })
          })
    })
})()
