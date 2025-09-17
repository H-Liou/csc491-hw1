
import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path

def main():
    # Paths
    repo = Path('.')
    csv_path = repo / 'results' / 'ipc_all.csv'
    out_dir = repo / 'results'
    out_dir.mkdir(parents=True, exist_ok=True)
    fig_path = out_dir / 'fig_ipc_per_workload.png'
    mean_csv = out_dir / 'mean_ipc.csv'

    # Load
    df = pd.read_csv(csv_path)
    # Expected columns: workload, policy, ipc
    if not set(['workload','policy','ipc']).issubset(df.columns):
        raise ValueError("ipc_all.csv must have columns: workload, policy, ipc")

    # Orderings
    wl_order = ['astar','lbm','mcf','milc','omnetpp']
    pol_order = ['LRU','LIME','YourBest','Ours','Best','DRRIP','DRRIP+SB+DB']
    # Normalize policy labels to a consistent set (handle minor variants)
    rename_map = {
        'YourBest': 'Ours',
        'Best': 'Ours',
        'DRRIP': 'Ours',
        'DRRIP+SB+DB': 'Ours',
        'drrip': 'Ours',
        'our': 'Ours',
        'ours': 'Ours'
    }
    df['policy'] = df['policy'].replace(rename_map)
    # Keep only known policies
    keep = df['policy'].isin(['LRU','LIME','Ours'])
    df = df.loc[keep].copy()

    # Categorical ordering
    df['workload'] = pd.Categorical(df['workload'], wl_order, ordered=True)
    df['policy']   = pd.Categorical(df['policy'], ['LRU','LIME','Ours'], ordered=True)

    # Pivot for plotting
    pivot = df.pivot(index='workload', columns='policy', values='ipc').loc[wl_order]

    # Plot
    ax = pivot.plot(kind='bar', figsize=(8,4.5))
    ax.set_ylabel('IPC')
    ax.set_xlabel('Workload')
    ax.set_title('IPC per workload (higher is better)')
    ax.legend(title='Policy')
    plt.tight_layout()
    plt.savefig(fig_path, dpi=200)

    # Means
    mean = df.groupby('policy')['ipc'].mean().to_frame('mean_ipc').loc[['LRU','LIME','Ours']]
    print(mean)
    mean.to_csv(mean_csv)

if __name__ == '__main__':
    main()
