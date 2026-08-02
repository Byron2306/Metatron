import * as React from "react"
import { cva } from "class-variance-authority";

import { cn } from "@/lib/utils"

// Cyberpunk pill — jagged angular shape, near-black bg, neon glow borders.
// Uses filter:drop-shadow so glow survives the clip-path clipping.
// The seraph-pill CSS class in index.css enforces shape + font globally.
const badgeVariants = cva(
  "seraph-pill seraph-ui-pill inline-flex items-center border px-2.5 py-0.5 text-xs font-bold uppercase tracking-widest transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2",
  {
    variants: {
      variant: {
        default:
          "bg-[#02050d] border-cyan-500/80 text-cyan-300",
        secondary:
          "bg-[#02050d] border-purple-500/80 text-purple-300",
        destructive:
          "bg-[#02050d] border-red-500/80 text-red-300",
        outline:
          "bg-[#02050d]/80 border-cyan-500/50 text-cyan-400",
        success:
          "bg-[#02050d] border-green-500/80 text-green-300",
        warning:
          "bg-[#02050d] border-yellow-500/80 text-yellow-300",
        pink:
          "bg-[#02050d] border-pink-500/80 text-pink-300",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  }
)

function Badge({
  className,
  variant,
  ...props
}) {
  return (<div className={cn(badgeVariants({ variant }), className)} {...props} />);
}

export { Badge, badgeVariants }
