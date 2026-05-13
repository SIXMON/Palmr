"use client";

import { useEffect, useState } from "react";
import { NextIntlClientProvider } from "next-intl";
import { parseCookies } from "nookies";

// Client-side locale loader. Why this exists:
//
// Under `output: "export"` every page is pre-rendered at build time with
// a single locale (NEXT_PUBLIC_DEFAULT_LANGUAGE). The legacy server-side
// path that read `cookies()` in i18n/request.ts is gone — `cookies()` is
// a Dynamic API that the export forbids. So we switch locales here, on
// the client, after hydration:
//
//   1. Server renders with the build-time locale → consistent SSR HTML.
//   2. Mount: read the `NEXT_LOCALE` cookie. If it differs from the
//      build-time locale, dynamic-import the matching messages JSON
//      (one chunk per locale ≈ 15 KB gzipped) and update the provider.
//   3. <html lang> + dir get updated to match, so RTL languages flip
//      direction without a flash.
//
// The LanguageSwitcher writes the cookie and triggers
// `window.location.reload()` so a fresh boot picks up the change for
// every consumer (translations, RTL, document title, etc).

const RTL_LANGUAGES = new Set(["ar-SA", "fa-IR", "he-IL"]);

const SUPPORTED_LOCALES = new Set([
  "en-US",
  "pt-BR",
  "fr-FR",
  "es-ES",
  "de-DE",
  "it-IT",
  "nl-NL",
  "pl-PL",
  "tr-TR",
  "ru-RU",
  "hi-IN",
  "ar-SA",
  "zh-CN",
  "ja-JP",
  "ko-KR",
  "th-TH",
  "vi-VN",
  "uk-UA",
  "fa-IR",
  "sv-SE",
  "id-ID",
  "el-GR",
  "he-IL",
]);

interface IntlClientProviderProps {
  initialLocale: string;
  initialMessages: Record<string, unknown>;
  children: React.ReactNode;
}

export function IntlClientProvider({ initialLocale, initialMessages, children }: IntlClientProviderProps) {
  const [locale, setLocale] = useState(initialLocale);
  const [messages, setMessages] = useState(initialMessages);

  // On mount: if the cookie names a different locale than the one baked
  // in at build time, fetch its messages and swap. The dynamic import
  // template literal is what makes webpack code-split the messages bundle
  // — without the literal it would have to inline all 23 files.
  useEffect(() => {
    const cookieLocale = parseCookies(null).NEXT_LOCALE;
    if (!cookieLocale || cookieLocale === initialLocale || !SUPPORTED_LOCALES.has(cookieLocale)) {
      return;
    }
    let cancelled = false;
    import(`../../messages/${cookieLocale}.json`)
      .then((mod) => {
        if (cancelled) return;
        setLocale(cookieLocale);
        setMessages(mod.default);
      })
      .catch(() => {
        // Network or chunk-load error — stay on the initial locale.
      });
    return () => {
      cancelled = true;
    };
  }, [initialLocale]);

  // Sync the document attributes after the locale actually changes. We
  // do this in an effect (rather than in render) to avoid touching the
  // server-rendered HTML and tripping the hydration mismatch warning.
  useEffect(() => {
    document.documentElement.lang = locale;
    document.documentElement.dir = RTL_LANGUAGES.has(locale) ? "rtl" : "ltr";
  }, [locale]);

  return (
    <NextIntlClientProvider locale={locale} messages={messages}>
      {children}
    </NextIntlClientProvider>
  );
}
