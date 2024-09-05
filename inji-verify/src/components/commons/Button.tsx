import React, { HTMLAttributes, ReactElement } from "react";

type StyledButtonProps = HTMLAttributes<HTMLButtonElement> & {
  id: string;
  title: string;
  fill?: boolean;
  iconLeft?: ReactElement;
  iconRight?: ReactElement;
};

function Button({
  id,
  title,
  fill,
  iconLeft,
  iconRight,
  className,
  ...props
}: StyledButtonProps) {
  return (
    <button
      {...props}
      className={
        `inline-flex content-center justify-center border-2 border-primary py-[12px] px-7 ` +
        `rounded-[9999px] hover:bg-primary bg-[#FFFFFF] ` +
        `hover:text-[#FFFFFF] text-primary ${className}`
      }
    >
      {iconLeft && <span className="inline-grid mr-1.5">{iconLeft}</span>}
      <span id={id} className="font-bold text-[16px] normal-case">
        {title}
      </span>
      {iconRight && <span className="inline-grid ml-1.5">{iconRight}</span>}
    </button>
  );
}

export default Button;
