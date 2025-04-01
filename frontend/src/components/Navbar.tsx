import Link from "next/link";
export default function Navbar() {
  return (
    <nav className="flex justify-between items-center py-2 mb-12">
      <Link href="/">
        <p className="text-2xl md:text-3xl italic cursor-pointer">round3.</p>
      </Link>
      <div className="flex gap-4 justify-center items-center">
        <Link href="/signin">
          <p className="text-sm hover:text-gray-300 cursor-pointer">Sign In</p>
        </Link>
        <Link href="/join">
          <p className="text-sm bg-white text-black px-4 py-1 rounded-full hover:bg-gray-200 cursor-pointer">
            Join
          </p>
        </Link>
      </div>
    </nav>
  );
}
