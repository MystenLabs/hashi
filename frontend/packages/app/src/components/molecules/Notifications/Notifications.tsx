import { cn } from '@/lib/utils';
import { Icon } from '@/components/atoms/Icon';
import { Button } from '@/components/atoms/Button';

type NotificationType = 'complete' | 'received' | 'failed';

export interface Notification {
	id: string;
	type: NotificationType;
	currency: 'BTC' | 'suiBTC';
	title: string;
	message: string;
	time: string;
	read: boolean;
}

interface NotificationsProps {
	notifications?: Notification[];
	className?: string;
	onClose?: () => void;
	onNotificationClick?: (id: string) => void;
	onClearAll?: () => void;
}

function NotificationItem({
	notification,
	onClick,
}: {
	notification: Notification;
	onClick?: () => void;
}) {
	return (
		<div
			onClick={onClick}
			className={cn(
				'flex cursor-pointer items-start gap-3 rounded-xs bg-white/24 px-4 py-3',
				notification.type === 'failed' &&
					'bg-white/12 bg-linear-0 from-[#FF6767]/24 to-[#FF6767]/24',
				notification.read && 'bg-white/12',
			)}
		>
			<div className="relative h-11 w-11 shrink-0">
				<Icon name={notification.currency} className="h-full w-full" />
				{notification.type === 'complete' && (
					<div className="bg-valid absolute inset-0 flex items-center justify-center rounded-xs text-black">
						<Icon name="Check" />
					</div>
				)}
				{notification.type === 'received' && (
					<div className="bg-valid absolute top-0 right-0 flex h-4 w-4 items-center justify-center rounded-xs text-black ring-1 ring-black">
						<Icon name="Check" className="h-3 w-3" />
					</div>
				)}
				{notification.type === 'failed' && (
					<div className="bg-error absolute top-0 right-0 flex h-4 w-4 items-center justify-center rounded-xs text-black ring-1 ring-black">
						<Icon name="Close" className="h-3 w-3" />
					</div>
				)}
			</div>

			<div className="flex grow flex-col gap-1">
				<div className="flex items-center justify-between">
					<div className="font-bold">{notification.title}</div>
					<div className="text-xs text-current/60">{notification.time}</div>
				</div>
				<div className="flex items-center justify-between">
					<div className="text-sm text-current/80">{notification.message}</div>
					<Icon name="CaretDown" className="h-4 w-4 -rotate-90" />
				</div>
			</div>
		</div>
	);
}

function NotificationSection({
	title,
	notifications,
	onNotificationClick,
}: {
	title: string;
	notifications: Notification[];
	onNotificationClick?: (id: string) => void;
}) {
	if (notifications.length === 0) return null;
	return (
		<div className="flex flex-col gap-3">
			<div className="font-book -my-0.5 leading-none text-current/60">{title}</div>
			{notifications.map((n) => (
				<NotificationItem
					key={n.id}
					notification={n}
					onClick={() => onNotificationClick?.(n.id)}
				/>
			))}
		</div>
	);
}

export function Notifications({
	notifications = [],
	onClose,
	onNotificationClick,
	onClearAll,
	className,
}: NotificationsProps) {
	return (
		<div className={cn('flex flex-col gap-6 rounded-xs bg-black p-6', className)}>
			<div className="flex items-center justify-between gap-4">
				<h3 className="-my-0.5 text-2xl leading-none font-medium text-white">Notifications</h3>
				<button aria-label="Close" className="flex text-white" onClick={onClose}>
					<Icon name="Close" />
				</button>
			</div>

			<NotificationSection
				title="Unread"
				notifications={notifications.filter((n) => !n.read)}
				onNotificationClick={onNotificationClick}
			/>
			<NotificationSection
				title="Read"
				notifications={notifications.filter((n) => n.read)}
				onNotificationClick={onNotificationClick}
			/>

			<Button variant="outline" onClick={onClearAll}>
				Clear All
			</Button>
		</div>
	);
}
