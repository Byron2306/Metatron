import React, { useState, useEffect } from 'react';
import { Badge } from '../components/ui/badge';
import { Button } from '../components/ui/button';

const JobCard = ({ job, fetchArtifacts, API }) => {
  const [artifacts, setArtifacts] = useState([]);
  const [loadingArtifacts, setLoadingArtifacts] = useState(false);

  useEffect(() => {
    let mounted = true;
    const load = async () => {
      setLoadingArtifacts(true);
      const res = await fetchArtifacts(job.id);
      if (!mounted) return;
      setArtifacts(res.artifacts || []);
      setLoadingArtifacts(false);
    };
    load();
    return () => { mounted = false };
  }, [job.id]);

  const download = (filename) => {
    const url = `${API_ROOT}/integrations/artifact/${job.id}/${encodeURIComponent(filename)}`;
    window.open(url, '_blank');
  };

  return (
    <div className="p-2 bg-slate-800/50 rounded border border-slate-700">
      <div className="flex justify-between items-center">
        <div>
          <p className="text-white font-medium">{job.tool} — {job.params?.domain || job.params?.collection || job.params?.runtime_target || ''}</p>
          <p className="text-slate-400 text-xs">Status: {job.status} • Updated: {new Date(job.updated_at).toLocaleString()}</p>
          {(job.result?.queue_id || job.result?.decision_id) && (
            <p className="text-amber-300 text-xs">
              queue: {job.result?.queue_id || 'n/a'} • decision: {job.result?.decision_id || 'pending'}
            </p>
          )}
          {job.result?.agent_id && (
            <p className="text-cyan-300 text-xs">
              agent: {job.result.agent_id} • command: {job.result?.command_id || 'n/a'} • command status: {job.result?.agent_command_status || 'pending'}
            </p>
          )}
        </div>
        <div>
          <Badge>{job.status}</Badge>
        </div>
      </div>

      <div className="mt-2">
        <p className="text-slate-400 text-xs mb-1">Artifacts:</p>
        {loadingArtifacts ? <p className="text-slate-500 text-xs">Loading...</p> : (
          artifacts.length ? (
            artifacts.map(a => (
              <div key={a} className="flex items-center justify-between">
                <span className="text-slate-300 text-sm">{a}</span>
                <Button size="sm" variant="ghost" onClick={() => download(a)}>Download</Button>
              </div>
            ))
          ) : (
            <p className="text-slate-500 text-xs">No artifacts</p>
          )
        )}
      </div>
      {job.result && (
        <div className="mt-2">
          <p className="text-slate-400 text-xs mb-1">Result:</p>
          <pre className="text-[11px] text-slate-300 bg-slate-900/60 rounded p-2 overflow-auto max-h-40">
            {JSON.stringify(job.result, null, 2)}
          </pre>
        </div>
      )}
    </div>
  )
}

export default JobCard;
