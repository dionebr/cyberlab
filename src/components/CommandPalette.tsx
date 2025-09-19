import { useState, useEffect } from "react";
import { Search, BookOpen, Target, Home, Command as CommandIcon } from "lucide-react";
import {
  Command,
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
} from "@/components/ui/command";
import { Button } from "@/components/ui/button";
import { useNavigate } from "react-router-dom";
import { useLanguage } from "@/hooks/useLanguage";

const commandItems = [
  {
    group: "Navigation",
    items: [
      { id: "home", title: "Home", icon: Home, path: "/" },
      { id: "learn", title: "Learn Mode", icon: BookOpen, path: "/learn" },
    ]
  },
  {
    group: "Learn Categories",
    items: [
      { id: "fundamentals", title: "Security Fundamentals", icon: BookOpen, path: "/learn/fundamentals" },
      { id: "web-security", title: "Web Security", icon: Target, path: "/learn/web-security" },
      { id: "network-security", title: "Network Security", icon: Target, path: "/learn/network-security" },
      { id: "os-security", title: "Operating Systems Security", icon: Target, path: "/learn/os-security" },
      { id: "programming-security", title: "Secure Programming", icon: Target, path: "/learn/programming-security" },
    ]
  },
  {
    group: "Learn Topics",
    items: [
      { id: "owasp-top10", title: "OWASP Top 10", icon: BookOpen, path: "/learn/fundamentals/owasp-top10" },
      { id: "secure-coding", title: "Secure Coding Principles", icon: BookOpen, path: "/learn/fundamentals/secure-coding" },
      { id: "linux-security", title: "Linux Security", icon: BookOpen, path: "/learn/os-security/linux-security" },
      { id: "windows-security", title: "Windows Security", icon: BookOpen, path: "/learn/os-security/windows-security" },
      { id: "python-security", title: "Secure Python", icon: BookOpen, path: "/learn/programming-security/python-security" },
      { id: "javascript-security", title: "Secure JavaScript", icon: BookOpen, path: "/learn/programming-security/javascript-security" },
    ]
  }
];

export const CommandPalette = () => {
  const [open, setOpen] = useState(false);
  const navigate = useNavigate();
  const { t } = useLanguage();

  useEffect(() => {
    const down = (e: KeyboardEvent) => {
      if (e.key === "k" && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        setOpen((open) => !open);
      }
    };

    document.addEventListener("keydown", down);
    return () => document.removeEventListener("keydown", down);
  }, []);

  const handleSelect = (path: string) => {
    navigate(path);
    setOpen(false);
  };

  return (
    <>
      <Button
        variant="outline"
        size="sm"
        onClick={() => setOpen(true)}
        className="relative justify-start text-sm text-muted-foreground w-64 pr-4 hover:bg-accent hover:text-accent-foreground"
      >
        <Search className="mr-2 h-4 w-4" />
        Search modules...
        <kbd className="pointer-events-none absolute right-2 top-1/2 -translate-y-1/2 select-none items-center gap-1 rounded border bg-muted px-1.5 font-mono text-[10px] font-medium opacity-100 flex">
          <span className="text-xs">⌘</span>K
        </kbd>
      </Button>

      <CommandDialog open={open} onOpenChange={setOpen}>
        <CommandInput placeholder="Type a command or search..." />
        <CommandList>
          <CommandEmpty>No results found.</CommandEmpty>
          {commandItems.map((group, index) => (
            <div key={group.group}>
              <CommandGroup heading={group.group}>
                {group.items.map((item) => {
                  const Icon = item.icon;
                  return (
                    <CommandItem
                      key={item.id}
                      onSelect={() => handleSelect(item.path)}
                      className="cursor-pointer"
                    >
                      <Icon className="mr-2 h-4 w-4" />
                      <span>{item.title}</span>
                    </CommandItem>
                  );
                })}
              </CommandGroup>
              {index < commandItems.length - 1 && <CommandSeparator />}
            </div>
          ))}
        </CommandList>
      </CommandDialog>
    </>
  );
};