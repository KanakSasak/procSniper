import { ReactNode } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { Shield, Settings, History, Activity } from 'lucide-react'

interface LayoutProps {
  children: ReactNode
}

function Layout({ children }: LayoutProps) {
  const location = useLocation()

  const navItems = [
    { path: '/', icon: Activity, label: 'Dashboard' },
    { path: '/config', icon: Settings, label: 'Configuration' },
    { path: '/history', icon: History, label: 'History' },
  ]

  return (
    <div className="flex h-screen bg-ps-dark text-white">
      {/* Sidebar */}
      <aside className="w-64 bg-ps-darker border-r border-ps-accent/30">
        {/* Logo */}
        <div className="p-6 border-b border-ps-accent/30">
          <div className="flex items-center gap-3">
            <Shield className="w-8 h-8 text-ps-primary" />
            <div>
              <h1 className="text-xl font-bold">procSniper</h1>
              <p className="text-xs text-gray-400">Ransomware Protection</p>
            </div>
          </div>
        </div>

        {/* Navigation */}
        <nav className="p-4">
          <ul className="space-y-2">
            {navItems.map((item) => {
              const isActive = location.pathname === item.path
              return (
                <li key={item.path}>
                  <Link
                    to={item.path}
                    className={`flex items-center gap-3 px-4 py-3 rounded-lg transition-colors ${
                      isActive
                        ? 'bg-ps-primary text-white'
                        : 'text-gray-400 hover:bg-ps-accent/50 hover:text-white'
                    }`}
                  >
                    <item.icon className="w-5 h-5" />
                    <span>{item.label}</span>
                  </Link>
                </li>
              )
            })}
          </ul>
        </nav>

        {/* Version */}
        <div className="absolute bottom-4 left-4 text-xs text-gray-500">
          v1.0.0
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 overflow-auto">
        {children}
      </main>
    </div>
  )
}

export default Layout
