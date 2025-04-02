export default function OnbaordingLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <div className="w-full min-h-screen font-calendas">
      <div className="py-12"></div>
      {children}
    </div>
  );
}
