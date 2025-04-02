export async function useAuth() {
  try {
    const response = await fetch("http://localhost:8000/login", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ username, password }),
    });

    const data = await response.json();

    if (response.ok && data.data.Token) {
      const token = data.data.Token;
      localStorage.setItem("token", token);
      router.push("/");
    }
  } catch (err) {}
}
