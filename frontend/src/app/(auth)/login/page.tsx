"use client";

import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import Link from "next/link";
import { useState } from "react";
import { useRouter } from "next/navigation";

export default function LoginComponet() {
  const [error, setError] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const router = useRouter();

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    try {
      console.log("inside the handleSubmit");
      const response = await fetch("http://localhost:8000/login", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ email, password }),
      });

      const data = await response.json();

      if (response.ok && data.data.Token) {
        const token = data.data.Token;
        localStorage.setItem("token", token);
        router.push("/");
      }
    } catch (err) {
      setError("An error occurred during login");
      console.error("Login error:", error);
    }
  };
  return (
    <div>
      <Card className="w-sm md:max-w-md mx-auto font-calendas p-4">
        <CardHeader>
          <CardTitle>
            <p className="text-center">Login</p>
          </CardTitle>
          <CardDescription>
            <p className="text-center">Enter you email and password to login</p>
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form
            method="POST"
            onSubmit={(event) => handleSubmit(event)}
            className="flex flex-col gap-4"
          >
            <div className="flex flex-col gap-2">
              <Label>Email</Label>
              <Input
                type="text"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="johndoe@gmail.com"
              ></Input>
            </div>
            <div className="flex flex-col gap-2">
              <Label>Password</Label>
              <Input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="password"
              ></Input>
            </div>
            <Button className="w-full" type="submit">
              Login
            </Button>
            <CardFooter className="flex flex-col gap-2">
              <Link href="/register" className="underline pt-4">
                Dont have an account? Create one
              </Link>
            </CardFooter>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
