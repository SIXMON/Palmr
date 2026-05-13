import { getRequestConfig } from "next-intl/server";

const supportedLocales = [
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
];

const envDefault = process.env.NEXT_PUBLIC_DEFAULT_LANGUAGE || "en-US";
const DEFAULT_LOCALE = supportedLocales.includes(envDefault) ? envDefault : "en-US";

// Static export: locale is baked at build time from NEXT_PUBLIC_DEFAULT_LANGUAGE.
// We deliberately don't read `cookies()` here — that's a server-only API
// (output:"export" disables it) and the build would fail on prerender. The
// runtime language switcher lives in apps/web/src/components/general/
// language-switcher.tsx and updates a NextIntlClientProvider on the
// client side instead, which keeps the cookie behaviour for the user
// without involving the server.
export default getRequestConfig(async ({ locale }) => {
  const resolvedLocale = locale || DEFAULT_LOCALE;
  const finalLocale = supportedLocales.includes(resolvedLocale) ? resolvedLocale : DEFAULT_LOCALE;

  try {
    return {
      locale: finalLocale,
      messages: (await import(`../../messages/${finalLocale}.json`)).default,
    };
  } catch {
    return {
      locale: DEFAULT_LOCALE,
      messages: (await import(`../../messages/${DEFAULT_LOCALE}.json`)).default,
    };
  }
});
