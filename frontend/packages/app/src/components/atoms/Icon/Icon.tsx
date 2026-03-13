import { cn } from '@/lib/utils';
import { icons, type IconName } from './icons';

interface IconProps {
	name: IconName;
	className?: string;
}

export function Icon({ name, className }: IconProps) {
	return <span className={cn('inline-flex shrink-0 w-5 h-5', className)}>{icons[name]}</span>;
}
