"use client";

import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import Link from "next/link";
import { useState } from "react";
import { useRouter } from "next/navigation";
import { colgroup } from "motion/react-client";

export default function RegisterComponent() {
  const [error, setError] = useState("");
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("");
  const router = useRouter();

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    try {
      console.log("inside the handleSubmit");
      const response = await fetch("http://localhost:8000/register", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ username, password, role, email }),
      });

      const data = await response.json();

      if (response.ok) {
        router.push("/login");
      } else {
        console.log(response);
        console.log(data.message);
        setError(data.message);
      }
    } catch (err) {
      setError(err);
      console.log("Internal Error");
      console.error("Login error:", error);
    }
  };
  return (
    <div>
      <Card className="w-sm md:max-w-md mx-auto font-calendas p-4">
        <CardHeader>
          <CardTitle>
            <p className="text-center">Register</p>
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
              <Label>Username</Label>
              <Input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="johndoe69"
              ></Input>
            </div>
            <div className="flex flex-col gap-2">
              <Label>Email</Label>
              <Input
                type="email"
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
            <div className="flex flex-col gap-2">
              <Label>Role</Label>
              <Select onValueChange={setRole}>
                <SelectTrigger className="w-full">
                  <SelectValue placeholder="Role" />
                </SelectTrigger>
                <SelectContent className="w-full">
                  <SelectItem value="Reader">Reader</SelectItem>
                  <SelectItem value="Founder">Founder</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <Button className="w-full mt-2" type="submit">
              Register
            </Button>
            {error && <p className="text-center text-red-600">{error}</p>}
            <CardFooter className="flex flex-col gap-2">
              <Link href="/login" className="underline pt-4">
                Have an account? Login
              </Link>
            </CardFooter>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
