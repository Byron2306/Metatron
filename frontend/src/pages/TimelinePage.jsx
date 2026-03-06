import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { 
  Clock, AlertTriangle, Shield, Activity, FileText,
  ChevronRight, RefreshCw, Download, Search, Filter,
  Calendar, User, Server, Zap, Eye, X
} from 'lucide-react';
import { toast } from 'sonner';

const envBackendUrl = (process.env.REACT_APP_BACKEND_URL || '').trim();
const API = !envBackendUrl || envBackendUrl === 'undefined' || envBackendUrl === 'null'
  ? ''
  : envBackendUrl.replace(/\/+$/, '');

const TimelinePage = () => {
  const [loading, setLoading] = useState(true);
  const [timelines, setTimelines] = useState([]);
  const [selectedTimeline, setSelectedTimeline] = useState(null);
  const [timelineData, setTimelineData] = useState(null);
  const [loadingTimeline, setLoadingTimeline] = useState(false);

  const fetchTimelines = async () => {
    setLoading(true);
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`${API}/api/timelines/recent?limit=20`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (response.ok) {
        const data = await response.json();
        setTimelines(data.timelines || []);
      }
    } catch (err) {
      console.error('Failed to fetch timelines:', err);
    } finally {
      setLoading(false);
    }
  };

  const loadTimeline = async (threatId) => {
    setLoadingTimeline(true);
    setSelectedTimeline(threatId);
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`${API}/api/timeline/${threatId}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (response.ok) {
        const data = await response.json();
        setTimelineData(data);
      } else {
        toast.error('Failed to load timeline');
      }
    } catch (err) {
      toast.error('Failed to load timeline');
    } finally {
      setLoadingTimeline(false);
    }
  };

  const exportTimeline = async (threatId, format) => {
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`${API}/api/timeline/${threatId}/export?format=${format}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (response.ok) {
        const data = await response.json();
        if (format === 'markdown') {
          const blob = new Blob([data.markdown], { type: 'text/markdown' });
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = `timeline_${threatId}.md`;
          a.click();
        } else {
          const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = `timeline_${threatId}.json`;
          a.click();
        }
        toast.success('Timeline exported');
      }
    } catch (err) {
      toast.error('Export failed');
    }
  };

  useEffect(() => {
    fetchTimelines();
  }, []);

  const formatDate = (isoString) => {
    return new Date(isoString).toLocaleString();
  };

  const getSeverityColor = (severity) => {
    const colors = {
      critical: 'bg-red-500/20 text-red-400 border-red-500/30',
      high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
      medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
      low: 'bg-green-500/20 text-green-400 border-green-500/30'
    };
    return colors[severity] || colors.medium;
  };

  const getEventIcon = (eventType) => {
    const icons = {
      detection: AlertTriangle,
      alert: Activity,
      response: Zap,
      quarantine: Shield,
      block: Shield,
      forensics: FileText,
      user_action: User
    };
    return icons[eventType] || Activity;
  };

  return (
    <div className="space-y-6" data-testid="timeline-page">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded bg-cyan-500/20">
            <Clock className="w-6 h-6 text-cyan-400" />
          </div>
          <div>
            <h1 className="text-2xl font-mono font-bold">Threat Timeline</h1>
            <p className="text-slate-400 text-sm">Reconstruct and analyze threat incidents</p>
          </div>
        </div>
        <button
          onClick={fetchTimelines}
          disabled={loading}
          className="flex items-center gap-2 px-4 py-2 bg-slate-700 hover:bg-slate-600 rounded"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Timeline List */}
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          className="bg-slate-800/50 border border-slate-700 rounded-lg overflow-hidden"
        >
          <div className="p-4 border-b border-slate-700">
            <h3 className="font-semibold">Recent Incidents</h3>
            <p className="text-xs text-slate-400">{timelines.length} threats with timelines</p>
          </div>
          
          <div className="max-h-[600px] overflow-y-auto">
            {loading ? (
              <div className="flex items-center justify-center py-12">
                <RefreshCw className="w-6 h-6 animate-spin text-cyan-400" />
              </div>
            ) : timelines.length === 0 ? (
              <div className="text-center py-12 text-slate-500">
                <Clock className="w-8 h-8 mx-auto mb-2 opacity-50" />
                <p>No threat timelines available</p>
              </div>
            ) : (
              timelines.map((t, idx) => (
                <motion.div
                  key={t.threat_id}
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: idx * 0.05 }}
                  onClick={() => loadTimeline(t.threat_id)}
                  className={`p-4 border-b border-slate-700 cursor-pointer hover:bg-slate-700/50 transition-colors ${
                    selectedTimeline === t.threat_id ? 'bg-cyan-500/10 border-l-2 border-l-cyan-500' : ''
                  }`}
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className={`px-2 py-0.5 rounded text-xs ${getSeverityColor(t.severity)}`}>
                      {t.severity}
                    </span>
                    <span className="text-xs text-slate-500">{t.event_count} events</span>
                  </div>
                  <p className="font-semibold text-sm truncate">{t.threat_name}</p>
                  <p className="text-xs text-slate-400 mt-1">{t.threat_type}</p>
                  <p className="text-xs text-slate-500 mt-1">{formatDate(t.first_seen)}</p>
                </motion.div>
              ))
            )}
          </div>
        </motion.div>

        {/* Timeline Detail */}
        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          className="lg:col-span-2 bg-slate-800/50 border border-slate-700 rounded-lg overflow-hidden"
        >
          {!selectedTimeline ? (
            <div className="flex items-center justify-center h-[600px] text-slate-500">
              <div className="text-center">
                <Eye className="w-12 h-12 mx-auto mb-3 opacity-50" />
                <p>Select a threat to view its timeline</p>
              </div>
            </div>
          ) : loadingTimeline ? (
            <div className="flex items-center justify-center h-[600px]">
              <RefreshCw className="w-8 h-8 animate-spin text-cyan-400" />
            </div>
          ) : timelineData ? (
            <>
              {/* Header */}
              <div className="p-4 border-b border-slate-700">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="font-semibold text-lg">{timelineData.threat_name}</h3>
                    <div className="flex items-center gap-3 mt-1">
                      <span className={`px-2 py-0.5 rounded text-xs ${getSeverityColor(timelineData.severity)}`}>
                        {timelineData.severity}
                      </span>
                      <span className="text-xs text-slate-400">{timelineData.threat_type}</span>
                      <span className={`text-xs px-2 py-0.5 rounded ${
                        timelineData.status === 'resolved' ? 'bg-green-500/20 text-green-400' :
                        timelineData.status === 'active' ? 'bg-red-500/20 text-red-400' :
                        'bg-slate-700 text-slate-400'
                      }`}>
                        {timelineData.status}
                      </span>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => exportTimeline(selectedTimeline, 'json')}
                      className="p-2 hover:bg-slate-700 rounded"
                      title="Export JSON"
                    >
                      <Download className="w-4 h-4" />
                    </button>
                    <button
                      onClick={() => exportTimeline(selectedTimeline, 'markdown')}
                      className="p-2 hover:bg-slate-700 rounded"
                      title="Export Markdown"
                    >
                      <FileText className="w-4 h-4" />
                    </button>
                  </div>
                </div>
                
                {/* Summary */}
                {timelineData.summary && (
                  <p className="text-sm text-slate-300 mt-3 p-3 bg-slate-900/50 rounded">
                    {timelineData.summary}
                  </p>
                )}
              </div>

              {/* Impact Assessment */}
              {timelineData.impact_assessment && (
                <div className="p-4 border-b border-slate-700 bg-slate-900/30">
                  <h4 className="text-sm font-semibold mb-2">Impact Assessment</h4>
                  <div className="grid grid-cols-3 gap-4 text-xs">
                    <div>
                      <span className="text-slate-400">Response Time</span>
                      <p className="font-mono text-white">
                        {timelineData.impact_assessment.response_time_minutes !== null
                          ? `${timelineData.impact_assessment.response_time_minutes} min`
                          : 'N/A'}
                      </p>
                    </div>
                    <div>
                      <span className="text-slate-400">Total Events</span>
                      <p className="font-mono text-white">{timelineData.impact_assessment.total_events}</p>
                    </div>
                    <div>
                      <span className="text-slate-400">Contained</span>
                      <p className={`font-mono ${timelineData.impact_assessment.contained ? 'text-green-400' : 'text-red-400'}`}>
                        {timelineData.impact_assessment.contained ? 'Yes' : 'No'}
                      </p>
                    </div>
                  </div>
                </div>
              )}

              {/* Events Timeline */}
              <div className="p-4 max-h-[350px] overflow-y-auto">
                <h4 className="text-sm font-semibold mb-4">Event Timeline</h4>
                <div className="relative">
                  <div className="absolute left-4 top-0 bottom-0 w-0.5 bg-slate-700"></div>
                  
                  {timelineData.events?.map((event, idx) => {
                    const Icon = getEventIcon(event.event_type);
                    return (
                      <motion.div
                        key={event.id}
                        initial={{ opacity: 0, x: -10 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ delay: idx * 0.05 }}
                        className="relative pl-10 pb-6"
                      >
                        <div className={`absolute left-2 w-5 h-5 rounded-full flex items-center justify-center ${
                          event.severity === 'critical' ? 'bg-red-500' :
                          event.severity === 'high' ? 'bg-orange-500' :
                          event.severity === 'warning' ? 'bg-yellow-500' :
                          'bg-cyan-500'
                        }`}>
                          <Icon className="w-3 h-3 text-white" />
                        </div>
                        
                        <div className="bg-slate-900/50 rounded p-3 border border-slate-700">
                          <div className="flex items-center justify-between mb-1">
                            <span className="font-semibold text-sm">{event.title}</span>
                            <span className="text-xs text-slate-500">{formatDate(event.timestamp)}</span>
                          </div>
                          <p className="text-xs text-slate-400">{event.description}</p>
                          <div className="flex items-center gap-2 mt-2 text-xs">
                            <span className="text-slate-500">{event.event_type}</span>
                            <span className="text-slate-600">•</span>
                            <span className="text-slate-500">{event.source}</span>
                          </div>
                        </div>
                      </motion.div>
                    );
                  })}
                </div>
              </div>

              {/* Recommendations */}
              {timelineData.recommendations?.length > 0 && (
                <div className="p-4 border-t border-slate-700 bg-amber-500/5">
                  <h4 className="text-sm font-semibold mb-2 text-amber-400">Recommendations</h4>
                  <ul className="text-xs space-y-1 text-slate-300">
                    {timelineData.recommendations.map((rec, idx) => (
                      <li key={idx} className="flex items-start gap-2">
                        <ChevronRight className="w-3 h-3 text-amber-400 flex-shrink-0 mt-0.5" />
                        {rec}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </>
          ) : null}
        </motion.div>
      </div>
    </div>
  );
};

export default TimelinePage;
