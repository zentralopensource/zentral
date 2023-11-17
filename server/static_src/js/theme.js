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
        if ( (theme === 'dark') || (theme === 'auto' && window.matchMedia('(prefers-color-scheme: dark)').matches) ) {
          document.documentElement.setAttribute('data-bs-theme', 'dark')
        }
        else {
          document.documentElement.setAttribute('data-bs-theme', 'light')
        }
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
