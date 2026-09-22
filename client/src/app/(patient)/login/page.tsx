/* eslint-disable @typescript-eslint/no-explicit-any */
"use client";

import type React from "react";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Eye, EyeOff, Shield } from "lucide-react";
import api from "@/lib/api";
import { useUser } from "@/context/UserContext";

// the API redirects back to /login?error=<code> when Google sign-in fails
const OAUTH_ERRORS: Record<string, string> = {
  oauth_failed: "Google sign-in failed. Please try again.",
  oauth_denied: "Google sign-in was cancelled.",
  oauth_unverified: "Your Google account's email address is not verified.",
  oauth_no_account:
    "No EVRS account is linked to that Google account. Add the same email to your EVRS profile, or sign in with your Citizen ID.",
  oauth_unavailable:
    "Google sign-in is currently unavailable. Please use your Citizen ID and password.",
};

export default function LoginPage() {
  const [showPassword, setShowPassword] = useState(false);
  const [citizenId, setCitizenId] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const router = useRouter();
  const { refreshProfiles } = useUser();

  useEffect(() => {
    const code = new URLSearchParams(window.location.search).get("error");
    if (code && OAUTH_ERRORS[code]) {
      setError(OAUTH_ERRORS[code]);
      // drop the query string so a refresh does not show the message again
      window.history.replaceState(null, "", window.location.pathname);
    }
  }, []);

  // full-page redirect: the API sends the browser to Google, then back to /dashboard
  const handleGoogleLogin = () => {
    window.location.href = `${api.defaults.baseURL}/auth/oauth/google`;
  };

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    if (!citizenId || !password) {
      setError("Please fill in all fields.");
      return;
    }

    try {
      await api.post("/auth/login/citizen", {
        citizenId,
        password,
      });

      await refreshProfiles();

      router.replace("/dashboard");
    } catch (err: any) {
      const msg =
        err.response?.data?.message || "Login failed. Please try again.";
      setError(msg);
      console.error("Login error:", err);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-primary-50 to-white flex items-center justify-center p-4">
      <div className="w-full max-w-md space-y-6">
        {/* header */}
        <div className="text-center space-y-2">
          <div className="flex items-center justify-center space-x-2 mb-4">
            <Shield className="h-8 w-8 text-primary-DEFAULT" />
            <h1 className="text-2xl font-bold text-primary-DEFAULT">EVRS</h1>
          </div>
          <p className="text-muted-foreground">
            Secure access to your vaccination records
          </p>
        </div>

        {/* login card */}
        <Card className="border-primary-DEFAULT/20 shadow-lg bg-white">
          <CardHeader className="space-y-1 text-center">
            <CardTitle className="text-xl text-primary-DEFAULT">
              Patient Login
            </CardTitle>
            <CardDescription>
              Enter your credentials to access your health records
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleLogin} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="citizenId">Citizen ID</Label>
                <Input
                  id="citizenId"
                  type="text"
                  placeholder="C1234567890"
                  value={citizenId}
                  onChange={(e) => {
                    setCitizenId(e.target.value);
                    if (error) setError("");
                  }}
                  required
                  className="mt-2 border-primary-DEFAULT/20 focus:border-primary-DEFAULT"
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="password">Password</Label>
                <div className="relative">
                  <Input
                    id="password"
                    type={showPassword ? "text" : "password"}
                    placeholder="Enter your password"
                    value={password}
                    onChange={(e) => {
                      setPassword(e.target.value);
                      if (error) setError("");
                    }}
                    required
                    className="mt-2 border-primary-DEFAULT/20 focus:border-primary-DEFAULT pr-10"
                  />
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent"
                    onClick={() => setShowPassword(!showPassword)}
                  >
                    {showPassword ? (
                      <Eye className="h-4 w-4 text-muted-foreground" />
                    ) : (
                      <EyeOff className="h-4 w-4 text-muted-foreground" />
                    )}
                  </Button>
                </div>
              </div>
              {error && (
                <div className="bg-red-50 border border-red-200 text-red-600 px-3 py-2 rounded-md text-sm">
                  {error}
                </div>
              )}

              <Button
                type="submit"
                className="w-full bg-primary-DEFAULT hover:bg-primary-600"
              >
                Sign In
              </Button>
            </form>

            <div className="relative my-5">
              <div className="absolute inset-0 flex items-center">
                <span className="w-full border-t border-primary-DEFAULT/20" />
              </div>
              <div className="relative flex justify-center text-xs uppercase">
                <span className="bg-white px-2 text-muted-foreground">or</span>
              </div>
            </div>

            <Button
              type="button"
              variant="outline"
              className="w-full border-primary-DEFAULT/20"
              onClick={handleGoogleLogin}
            >
              <svg
                className="mr-2 h-4 w-4"
                viewBox="0 0 24 24"
                aria-hidden="true"
              >
                <path
                  fill="#4285F4"
                  d="M23.5 12.3c0-.8-.1-1.6-.2-2.3H12v4.5h6.5a5.5 5.5 0 0 1-2.4 3.6v3h3.9c2.3-2.1 3.5-5.2 3.5-8.8z"
                />
                <path
                  fill="#34A853"
                  d="M12 24c3.2 0 6-1.1 7.9-2.9l-3.9-3c-1.1.7-2.5 1.2-4 1.2-3.1 0-5.7-2.1-6.6-4.9H1.4v3.1A12 12 0 0 0 12 24z"
                />
                <path
                  fill="#FBBC05"
                  d="M5.4 14.4a7.2 7.2 0 0 1 0-4.8V6.5H1.4a12 12 0 0 0 0 10.9l4-3z"
                />
                <path
                  fill="#EA4335"
                  d="M12 4.8c1.7 0 3.3.6 4.5 1.8l3.4-3.4A12 12 0 0 0 1.4 6.5l4 3.1C6.3 6.9 8.9 4.8 12 4.8z"
                />
              </svg>
              Continue with Google
            </Button>

            <div className="mt-6 space-y-4">
              <div className="text-center">
                <Button
                  variant="link"
                  className="text-primary-DEFAULT text-sm"
                  onClick={() => router.push("/forgot-password")}
                >
                  Forgot your password?
                </Button>
              </div>

              <div className="text-center text-sm text-muted-foreground">
                Need help accessing your account?{" "}
                <Button
                  variant="link"
                  className="text-primary-DEFAULT p-0 h-auto"
                >
                  Contact Support
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* footer */}
        <div className="text-center text-xs text-muted-foreground space-y-1">
          <p>This is a secure GOV-approved portal</p>
          <p>Your data is protected and encrypted</p>
        </div>
      </div>
    </div>
  );
}
