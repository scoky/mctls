% opt - graph type 
% remote - local or remote experiment

function [] = plotHandshake(opt, remote) 

% Common variables 
folder = '/home/varvello/WorkTelefonica/HTTP-2/results'; 
figFolder = './fig';
kind_line = ['m';'b';'g';'m';'b';'g';'m';'b';'g';'m';'o';':';'d';'+';'<';'s';'.';'-';'g';'p'];
line_style = ['-';';';':'];
N_slices=1;

% Close figures 
close all 

% Plotting protocol usage evolution over time
protocol = [
	'fwd'
	'ssl'
	'spp'
	]; 
	%'spp_mod'
	%]; 
% Plotting protocol usage evolution over time
leg= [
	'TLS (forwarding)'
	'TLS (splitting) '
	'SPP             '
	]; 
	%'SPP (modified)  '
	%]; 

nProt = size(protocol, 1); 
handshakeTime = figure(); 
hold on 

% Load data to plot from files 
counter = 1;
if (opt == 2) 
	if (remote == 0) 
		suffix = 'timeFirstByte_slice'; 
	else
		suffix = 'remote_timeFirstByte_slice'; 
	end	
end
if (opt == 3) 
	suffix = 'timeFirstByte_latency'; 
end
if (opt == 4) 
	suffix = 'timeFirstByte_proxy'; 
end
if (opt == 5) 
	suffix = 'downloadTime'; 
end
if (opt == 6) 
	suffix = 'downloadTime_browser'; 
end



% Main loop 
for ii = 1 : nProt
	currProt = strtrim(protocol(ii, :)); 
	file = sprintf('res_%s_%s', currProt, suffix); 
	data = dlmread(file); 
	if (opt < 5) 
		if (remote == 1)  
			h = errorbar(data(:, 3).*1000, data(:, 4).*1000); 
		else 
			h = errorbar(data(:, 4).*1000, data(:, 5).*1000); 
		end
	elseif (opt == 5) 
			h = errorbar(data(:, 4), data(:, 5)); 
	elseif (opt == 6) 
			h = cdfplot(data(:, 4)); 
			% h1 = cdfplot(data(:, 5)); % here we can plot CDF of stdev...
	end
	if (ii > 3) 
		set (h, 'color', kind_line(counter), 'LineWidth', 3, 'LineStyle', '--');
	else 
		set (h, 'color', kind_line(counter), 'LineWidth', 3);
	end
	%if (ii == 1)
	%	leg = {sprintf('%s',currProt)};
	%else
	%	leg = [leg, {sprintf('%s', currProt)}];
	%end
	counter = counter + 1; 
	if (opt == 2) 
		rtt = data(1, 2); 
		N = data(1, 3); 
	end
	if (opt == 3)
		N_slices = data(1, 2);
		N = data(1, 3); 
	end
	if (opt == 4 || opt == 5 || opt == 6)
		N_slices = data(1, 2);
		rtt = data(1, 3); 
	end
end

% X axis labels
if (opt == 2) 
	xlabel('No. slices (#)');
end
if (opt == 3) 
	xlabel('Network Latency (ms)');
end
if (opt == 4) 
	xlabel('No. proxies (#)');
end
if (opt == 5) 
	xlabel('File size (KB)');
end
if (opt == 6) 
	xlabel('Download Time (ms)');
end
% Y axis labels
if (opt < 5) 
	ylabel('Time to First Byte (ms)');
elseif (opt == 5) 
	ylabel('Download Time (sec)');
elseif (opt == 6) 
	ylabel('CDF (0-1)');
end

% More plot details 
legend(leg, 'Location', 'NorthWest');
grid on 
set(0,'defaultaxesfontsize',18);

% derive title based on input 
if (opt == 2) 
	if (remote == 0)  
		t = sprintf('Latency=%dms ; N_{prxy}=%d ; LOCAL', rtt, N); 
	else
		t = sprintf('N_{prxy}=%d ; AMAZON',  N); 
	end
end
if (opt == 3) 
	if (remote == 0)  
		t = sprintf('S=%d ; N_{prxy}=%d ; LOCAL', N_slices, N); 
	end
end
if (opt == 4)
	if (remote == 0)  
		t = sprintf('S=%d ; Latency=%dms ; LOCAL', N_slices, rtt); 
	end
end
if (opt == 5) 
	if (remote == 0)  
		t = sprintf('S=%d ; Latency=%dms; Rate=5Mbps ; LOCAL', N_slices, rtt); 
	end
end
if (opt == 6) 
	if (remote == 0)  
		t = sprintf('S=%d ; Latency=%dms ; LOCAL', N_slices, rtt); 
	else
		t = sprintf('S=%d ; AMAZON', N_slices, rtt); 
	end
end

% set title
title(t);

% set xtick label correctly 
xlim([1 size(data, 1)]); 
X = 1:size(data, 1); 
set(gca, 'XTick', X, 'XTickLabel', data(:, 1)'); 
%set(gca, 'XTickLabel', [5; 10; 20]); 
%if (opt == 3) 
%	set(gca, 'YScale','log'); 
%end
if (opt == 2)
	if (remote == 0)  
		outFile = sprintf ('%s/time_1st_byte_slice.eps', figFolder); 
	else
		outFile = sprintf ('%s/time_1st_byte_slice_remote.eps', figFolder); 
	end
end
if (opt == 3) 
	outFile = sprintf ('%s/time_1st_byte_latency.eps', figFolder); 
end
if (opt == 4) 
	outFile = sprintf ('%s/time_1st_byte_proxy.eps', figFolder); 
end
if (opt == 5) 
	if (remote == 0)  
		outFile = sprintf ('%s/download_time_fSize.eps', figFolder); 
	else
		outFile = sprintf ('%s/download_time_fSize_remote.eps', figFolder); 
	end	
end
if (opt == 6) 
	if (remote == 0)  
		outFile = sprintf ('%s/download_time_browser-like.eps', figFolder); 
	else
		outFile = sprintf ('%s/download_time_browser-like_remote.eps', figFolder); 
	end
end

% Saving file 
saveas (h, outFile, 'psc2');

