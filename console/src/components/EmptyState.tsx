interface Props {
  icon?: string;
  title: string;
  body: string;
}

export function EmptyState({ icon = '✓', title, body }: Props) {
  return (
    <div className="empty">
      <div className="empty-ico">{icon}</div>
      <h3>{title}</h3>
      <p>{body}</p>
    </div>
  );
}
