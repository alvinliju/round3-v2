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

export default function OnboardingComponent() {
  const [error, setError] = useState("");
  const [bio, setBio] = useState("");
  const [profile, setProfile] = useState("");
  const [websiteUrl, setWebsiteUrl] = useState("");
  const [twitter, setTwitter] = useState("");

  const router = useRouter();

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    try {
      const token = localStorage.getItem("token");
      console.log("inside the handleSubmit");
      const response = await fetch("http://localhost:8000/onboarding", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `${token}`,
        },
        body: JSON.stringify({
          bio,
          profileUrl: profile,
          website: websiteUrl,
          twitter,
        }),
      });

      const data = await response.json();

      if (response.ok) {
        router.push("/");
      }
    } catch (err) {
      setError("An error occurred during login");
      console.error("Login error:", error);
    }
  };
  return (
    <div>
      <Card className="w-sm md:max-w-md mx-auto font-calendas">
        <CardHeader>
          <CardTitle>
            <p className="text-center">Setup your founder profile</p>
          </CardTitle>
          <CardDescription>
            <p className="text-center">
              Setup your public founder profile now..
            </p>
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form
            method="POST"
            onSubmit={(event) => handleSubmit(event)}
            className="flex flex-col gap-4"
          >
            <div className="flex flex-col gap-2">
              <Label>Profile Url</Label>
              <Input
                type="text"
                value={profile}
                onChange={(e) => setProfile(e.target.value)}
                placeholder="johndoe@gmail.com"
              ></Input>
            </div>
            <div className="flex flex-col gap-2">
              <Label>Bio</Label>
              <Input
                type="text"
                value={bio}
                onChange={(e) => setBio(e.target.value)}
                placeholder="write a cool bio here"
              ></Input>
            </div>
            <div className="flex flex-col gap-2">
              <Label>What are you working on?</Label>
              <Input
                type="text"
                value={websiteUrl}
                onChange={(e) => setWebsiteUrl(e.target.value)}
                placeholder="https://round3.xyz"
              ></Input>
            </div>
            <div className="flex flex-col gap-2">
              <Label>Your twitter handle link</Label>
              <Input
                type="text"
                value={twitter}
                onChange={(e) => setTwitter(e.target.value)}
                placeholder="https://x.com/e3he0"
              ></Input>
            </div>
            <Button className="w-full" type="submit">
              Finish onboarding
            </Button>
            <CardFooter className="flex flex-col gap-2"></CardFooter>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
