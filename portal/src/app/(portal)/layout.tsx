import Shell from "@/components/Shell";
import AIAssistant from "@/components/AIAssistant";

export default function PortalLayout({ children }: { children: React.ReactNode }) {
  return (
    <>
      <Shell>{children}</Shell>
      <AIAssistant />
    </>
  );
}
