import { useState, useRef, useEffect } from 'react'
import { useMutation } from '@tanstack/react-query'
import { Layout } from '@/components/layout/Layout'
import { aiApi } from '@/api/threat.api'
import { Send, Bot, User, Sparkles, Loader2, AlertCircle, Zap } from 'lucide-react'
import ReactMarkdown from 'react-markdown'
import clsx from 'clsx'

interface Message {
  id: string
  role: 'user' | 'assistant'
  content: string
  timestamp: Date
}

const STARTER_QUESTIONS = [
  'What is SQL Injection and how do I prevent it?',
  'How does XSS work and what are its types?',
  'Explain the OWASP Top 10',
  'How do I detect and stop brute force attacks?',
  'What is Zero Trust architecture?',
]

export function AiPage() {
  const [messages, setMessages] = useState<Message[]>([
    {
      id: '0',
      role: 'assistant',
      content: `**Hello! I'm the Zero Trust Security Assistant.**

I can help you understand security threats, explain incidents, and provide remediation guidance.

**I can answer questions about:**
- SQL Injection, XSS, Brute Force, Path Traversal
- OWASP Top 10 vulnerabilities
- Zero Trust security principles
- Incident analysis and remediation
- Security best practices

*Ask me anything about security!*`,
      timestamp: new Date(),
    }
  ])
  const [input, setInput] = useState('')
  const bottomRef = useRef<HTMLDivElement>(null)

  const chatMutation = useMutation({
    mutationFn: (question: string) => aiApi.chat(question),
    onSuccess: (data) => {
      setMessages((prev) => [...prev, {
        id: Date.now().toString(),
        role: 'assistant',
        content: data.answer,
        timestamp: new Date(),
      }])
    },
    onError: () => {
      setMessages((prev) => [...prev, {
        id: Date.now().toString(),
        role: 'assistant',
        content: '❌ Sorry, I encountered an error. Please try again.',
        timestamp: new Date(),
      }])
    },
  })

  const sendMessage = (text: string) => {
    const q = text.trim()
    if (!q) return
    setMessages((prev) => [...prev, {
      id: Date.now().toString(),
      role: 'user',
      content: q,
      timestamp: new Date(),
    }])
    setInput('')
    chatMutation.mutate(q)
  }

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      sendMessage(input)
    }
  }

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  return (
    <Layout title="AI Security Assistant" subtitle="RAG-powered security intelligence (Gemini AI)">
      <div className="grid grid-cols-12 gap-4 h-[calc(100vh-10rem)]">

        {/* Sidebar — Starters */}
        <div className="col-span-12 lg:col-span-3 flex flex-col gap-3">
          <div className="card p-4">
            <div className="flex items-center gap-2 mb-3">
              <Sparkles className="w-4 h-4 text-brand-400" />
              <p className="text-sm font-semibold text-slate-200">Quick Questions</p>
            </div>
            <div className="space-y-2">
              {STARTER_QUESTIONS.map((q) => (
                <button key={q} onClick={() => sendMessage(q)}
                  className="w-full text-left text-xs text-slate-400 hover:text-slate-200 p-2.5 rounded-lg bg-surface-700 hover:bg-surface-600 transition-all duration-150 border border-transparent hover:border-brand-500/20">
                  {q}
                </button>
              ))}
            </div>
          </div>

          <div className="card p-4">
            <div className="flex items-center gap-2 mb-3">
              <AlertCircle className="w-4 h-4 text-amber-400" />
              <p className="text-sm font-semibold text-slate-200">AI Status</p>
            </div>
            <div className="space-y-2 text-xs">
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                <span className="text-slate-400">Security Knowledge Base</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-amber-400" />
                <span className="text-slate-400">Gemini API (requires key)</span>
              </div>
              <p className="text-slate-600 mt-2 leading-relaxed">
                Set <code className="text-slate-400">app.ai.enabled=true</code> and provide your Gemini API key for full AI responses.
              </p>
            </div>
          </div>
        </div>

        {/* Chat Area */}
        <div className="col-span-12 lg:col-span-9 card flex flex-col overflow-hidden">
          {/* Messages */}
          <div className="flex-1 overflow-y-auto p-4 space-y-4">
            {messages.map((msg) => (
              <div key={msg.id} className={clsx('flex gap-3', msg.role === 'user' ? 'flex-row-reverse' : 'flex-row')}>
                {/* Avatar */}
                <div className={clsx(
                  'w-8 h-8 rounded-xl flex items-center justify-center shrink-0 mt-0.5',
                  msg.role === 'assistant'
                    ? 'bg-gradient-to-br from-brand-500 to-violet-600 shadow-lg shadow-brand-500/20'
                    : 'bg-surface-600 border border-slate-600'
                )}>
                  {msg.role === 'assistant'
                    ? <Bot className="w-4 h-4 text-white" />
                    : <User className="w-4 h-4 text-slate-300" />}
                </div>

                {/* Bubble */}
                <div className={clsx(
                  'max-w-[85%] rounded-2xl px-4 py-3 text-sm leading-relaxed',
                  msg.role === 'assistant'
                    ? 'bg-surface-700 border border-slate-700/50 text-slate-200 rounded-tl-md'
                    : 'bg-gradient-to-br from-brand-600/80 to-violet-600/80 text-white rounded-tr-md'
                )}>
                  {msg.role === 'assistant' ? (
                    <div className="prose prose-invert prose-sm max-w-none prose-headings:text-slate-100 prose-strong:text-slate-100 prose-code:text-brand-300 prose-code:bg-surface-800 prose-code:px-1 prose-code:rounded">
                      <ReactMarkdown>{msg.content}</ReactMarkdown>
                    </div>
                  ) : (
                    <p>{msg.content}</p>
                  )}
                  <p className={clsx(
                    'text-xs mt-2 opacity-50',
                    msg.role === 'user' ? 'text-right' : 'text-left'
                  )}>
                    {msg.timestamp.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' })}
                  </p>
                </div>
              </div>
            ))}

            {/* Typing Indicator */}
            {chatMutation.isPending && (
              <div className="flex gap-3">
                <div className="w-8 h-8 rounded-xl bg-gradient-to-br from-brand-500 to-violet-600 flex items-center justify-center shrink-0">
                  <Bot className="w-4 h-4 text-white" />
                </div>
                <div className="bg-surface-700 border border-slate-700/50 rounded-2xl rounded-tl-md px-4 py-3 flex items-center gap-2">
                  <Loader2 className="w-4 h-4 text-brand-400 animate-spin" />
                  <span className="text-sm text-slate-400">Analyzing…</span>
                </div>
              </div>
            )}
            <div ref={bottomRef} />
          </div>

          {/* Input */}
          <div className="border-t border-slate-700/50 p-4">
            <div className="flex gap-2 items-end">
              <div className="flex-1 relative">
                <textarea
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  onKeyDown={handleKeyDown}
                  placeholder="Ask about security threats, vulnerabilities, or incidents…"
                  rows={2}
                  className="input-dark resize-none pr-4"
                />
              </div>
              <button
                onClick={() => sendMessage(input)}
                disabled={!input.trim() || chatMutation.isPending}
                id="ai-send-btn"
                className="btn-primary h-10 px-4 shrink-0"
              >
                {chatMutation.isPending ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <Send className="w-4 h-4" />
                )}
              </button>
            </div>
            <p className="text-xs text-slate-600 mt-2 flex items-center gap-1">
              <Zap className="w-3 h-3" />
              Press Enter to send • Shift+Enter for new line
            </p>
          </div>
        </div>

      </div>
    </Layout>
  )
}
