import {
  Inter,
  Lato,
  Montserrat,
  Nunito,
  Open_Sans,
  Outfit,
  Poppins,
  Raleway,
  Roboto,
  Source_Sans_3,
  Work_Sans,
} from "next/font/google";
import { getLocale, getMessages } from "next-intl/server";

import "./globals.css";

import { RedirectHandler } from "@/components/auth/redirect-handler";
import { Favicon } from "@/components/layout/favicon";
import { DynamicToaster } from "@/components/ui/dynamic-toaster";
import { useAppInfo } from "@/contexts/app-info-context";
import { AuthProvider } from "@/contexts/auth-context";
import { ShareProvider } from "@/contexts/share-context";
import { IntlClientProvider } from "../providers/intl-client-provider";
import { ThemeColorProvider } from "../providers/theme-color-provider";
import { ThemeProvider } from "../providers/theme-provider";

const outfit = Outfit({
  subsets: ["latin"],
  variable: "--font-outfit",
  weight: ["100", "200", "300", "400", "500", "600", "700", "800", "900"],
  display: "swap",
});

const inter = Inter({
  subsets: ["latin"],
  variable: "--font-inter",
  display: "swap",
});

const roboto = Roboto({
  subsets: ["latin"],
  variable: "--font-roboto",
  weight: ["100", "300", "400", "500", "700", "900"],
  display: "swap",
});

const openSans = Open_Sans({
  subsets: ["latin"],
  variable: "--font-open-sans",
  display: "swap",
});

const poppins = Poppins({
  subsets: ["latin"],
  variable: "--font-poppins",
  weight: ["100", "200", "300", "400", "500", "600", "700", "800", "900"],
  display: "swap",
});

const nunito = Nunito({
  subsets: ["latin"],
  variable: "--font-nunito",
  display: "swap",
});

const lato = Lato({
  subsets: ["latin"],
  variable: "--font-lato",
  weight: ["100", "300", "400", "700", "900"],
  display: "swap",
});

const montserrat = Montserrat({
  subsets: ["latin"],
  variable: "--font-montserrat",
  display: "swap",
});

const sourceSans = Source_Sans_3({
  subsets: ["latin"],
  variable: "--font-source-sans",
  display: "swap",
});

const raleway = Raleway({
  subsets: ["latin"],
  variable: "--font-raleway",
  display: "swap",
});

const workSans = Work_Sans({
  subsets: ["latin"],
  variable: "--font-work-sans",
  display: "swap",
});

export default async function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  // Build-time locale: with `output: "export"` this is the value returned
  // by getLocale() from the i18n/request.ts config, i.e.
  // NEXT_PUBLIC_DEFAULT_LANGUAGE. The client provider below reads the
  // user's NEXT_LOCALE cookie on mount and swaps to that locale's
  // messages bundle if it differs.
  const locale = await getLocale();
  const messages = await getMessages();
  const isRTL = locale === "ar-SA";

  if (typeof window !== "undefined") {
    useAppInfo.getState().refreshAppInfo();
  }

  return (
    <html lang={locale} dir={isRTL ? "rtl" : "ltr"} suppressHydrationWarning>
      <head>
        <Favicon />
      </head>
      <body
        className={`${outfit.variable} ${inter.variable} ${roboto.variable} ${openSans.variable} ${poppins.variable} ${nunito.variable} ${lato.variable} ${montserrat.variable} ${sourceSans.variable} ${raleway.variable} ${workSans.variable} font-sans antialiased`}
      >
        <IntlClientProvider initialLocale={locale} initialMessages={messages}>
          <ThemeProvider attribute="class" defaultTheme="system" enableSystem disableTransitionOnChange>
            <ThemeColorProvider>
              <AuthProvider>
                <RedirectHandler>
                  <ShareProvider>{children}</ShareProvider>
                </RedirectHandler>
              </AuthProvider>
              <DynamicToaster />
            </ThemeColorProvider>
          </ThemeProvider>
        </IntlClientProvider>
      </body>
    </html>
  );
}
