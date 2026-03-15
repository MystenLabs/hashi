import { cn } from '@/lib/utils';
import { Icon } from '@/components/atoms/Icon';
import { Button } from '@/components/atoms/Button';

interface SettingsProps {
	onClose?: () => void;
	onSave?: () => void;
	className?: string;
}

function Checkbox({ label, className }: { label: string; className?: string }) {
	return (
		<label className={cn('flex cursor-pointer items-center gap-2.5', className)}>
			<input type="checkbox" className="peer hidden" />
			<span className="peer-checked:bg-yellow peer-hover:ring-yellow relative flex h-6 w-6 shrink-0 items-center justify-center rounded-xs text-black ring-1 ring-white/48 transition ring-inset">
				<Icon name="Check" className="h-4 w-4" />
			</span>
			<span className="font-book">{label}</span>
		</label>
	);
}

export function Settings({ onClose, onSave, className }: SettingsProps) {
	return (
		<div
			className={cn(
				'flex w-full flex-col gap-8 rounded-xs bg-black p-6 ring-1 ring-white/16 ring-inset md:p-8',
				className,
			)}
		>
			{/* Title */}
			<div className="flex items-center justify-between gap-4">
				<h3 className="-my-0.5 text-2xl leading-none font-medium text-white">Settings</h3>
				<button aria-label="Close" className="flex text-white" onClick={onClose}>
					<Icon name="Close" />
				</button>
			</div>

			{/* Notifications */}
			<div className="flex flex-col gap-3">
				<div className="font-book text-current/60">Notifications</div>
				<Checkbox label="Send push notifications to connected SUI wallet app" />
				<div className="border-t border-white/10" />
				<div className="group">
					<Checkbox label="Send email notifications" className="peer" />
					<div className="mt-3 hidden group-has-checked:block">
						<input
							type="email"
							placeholder="Enter email address to receive notifications"
							className="h-auto w-full appearance-none rounded-xs bg-white/12 px-4 py-3 ring-1 ring-white/24 ring-inset focus:outline-0 md:py-3.5 md:text-lg"
						/>
					</div>
				</div>
			</div>

			{/* Network */}
			<div className="flex flex-col gap-3">
				<div className="font-book text-current/60">Network</div>
				<div className="font-book relative grid grid-cols-2 rounded-xs bg-white/12 text-center text-current/80">
					<label className="cursor-pointer rounded-xs p-2.5 transition-colors has-checked:bg-white/16 has-checked:font-bold has-checked:text-white">
						<input type="radio" defaultChecked name="network" value="mainnet" className="hidden" />
						<span>Mainnet</span>
					</label>
					<label className="cursor-pointer rounded-xs p-2.5 transition-colors has-checked:bg-white/16 has-checked:font-bold has-checked:text-white">
						<input type="radio" name="network" value="testnet" className="hidden" />
						<span>Testnet</span>
					</label>
				</div>
			</div>

			{/* Language */}
			<div className="flex flex-col gap-3">
				<div className="font-book text-current/60">Language</div>
				<div className="relative">
					<select className="h-auto w-full appearance-none rounded-xs bg-white/12 px-4 py-3 ring-1 ring-white/24 ring-inset focus:outline-0 md:py-3.5 md:text-lg">
						<option value="en-us">🇺🇸&nbsp; English - US</option>
						<option value="en-gb">🇬🇧&nbsp; English - GB</option>
						<option value="sp">🇪🇸&nbsp; Spanish</option>
						<option value="fr">🇫🇷&nbsp; French</option>
						<option value="de">🇩🇪&nbsp; German</option>
					</select>
					<Icon name="CaretDown" className="pointer-events-none absolute right-4 h-full opacity-60" />
				</div>
			</div>

			{/* Save */}
			<Button variant="secondary" onClick={onSave}>
				Save Settings
			</Button>
		</div>
	);
}
