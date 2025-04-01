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
import { colgroup } from "motion/react-client";

export default function LoginComponet() {
  const [error, setError] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    try {
      console.log("inside the handleSubmit");
      const response = await fetch("http://localhost:8000/login", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ username, password }),
      });

      const data = await response.json();

      console.log(data);
    } catch (err) {
      setError("An error occurred during login");
      console.error("Login error:", error);
    }
  };
  return (
    <div>
      <Card className="max-w-md mx-auto font-calendas">
        <CardHeader>
          <CardTitle>Login</CardTitle>
          <CardDescription>
            Enter you email and password to login
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
                value={username}
                onChange={(e) => setUsername(e.target.value)}
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
            <CardFooter className="flex flex-col gap-2">
              <Button className="w-full" type="submit">
                Login
              </Button>
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
